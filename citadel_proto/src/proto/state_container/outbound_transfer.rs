//! Outbound transfer acknowledgement handling for [`StateContainerInner`]:
//! group-header acks, file-header acks, and wave acks.

use super::includes::*;
use citadel_io::{error, ErrorCode, Dbg};

impl<R: Ratchet> StateContainerInner<R> {
    pub fn on_file_header_ack_received(
        &mut self,
        success: bool,
        session_cid: u64,
        ticket: Ticket,
        object_id: ObjectId,
        v_target: VirtualTargetType,
        _transfer_type: TransferType,
    ) -> Result<(), NetworkError> {
        let (key, receiver_cid) = match v_target {
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _target_cid,
            } => {
                let receiver_cid = session_cid;
                // since the order hasn't flipped yet, get the implicated cid
                (FileKey::new(object_id), receiver_cid)
            }

            VirtualConnectionType::LocalGroupServer { session_cid } => {
                (FileKey::new(object_id), session_cid)
            }

            _ => {
                return Err(error!(ErrorCode::FileTransferHyperWanAckUnsupported));
            }
        };

        if success {
            // remove the outbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.get_mut(&key) {
                let metadata = file_transfer.metadata.clone();
                // start the async task pulling from the async cryptscrambler
                file_transfer
                    .start
                    .take()
                    .ok_or_else(|| {
                        error!(ErrorCode::FileTransferAlreadyStarted, Dbg(key))
                    })?
                    .send(true)
                    .map_err(|_| {
                        error!(ErrorCode::FileTransferScramblerStartFailed, Dbg(key))
                    })?;
                let (handle, tx) = ObjectTransferHandler::new(
                    session_cid,
                    receiver_cid,
                    metadata,
                    ObjectTransferOrientation::Sender,
                    None,
                );
                tx.send(ObjectTransferStatus::TransferBeginning)
                    .map_err(|err| {
                        error!(ErrorCode::FileTransferBeginningStatusFailed, Dbg(key), err.to_string())
                    })?;
                let _ = self
                    .file_transfer_handles
                    .insert(key, crate::proto::outbound_sender::UnboundedSender(tx));
                // alert the kernel that file transfer has begun
                self.kernel_tx
                    .unbounded_send(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                        ticket,
                        handle,
                        session_cid,
                    }))
                    .map_err(|err| {
                        error!(ErrorCode::FileTransferHandleAlertFailed, Dbg(key), err.to_string())
                    })?;
            } else {
                return Err(error!(ErrorCode::FileTransferOutboundMissing, Dbg(key)));
            }
        } else {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.remove(&key) {
                // stop the async cryptscrambler
                file_transfer
                    .stop_tx
                    .ok_or_else(|| {
                        error!(ErrorCode::FileTransferStopSignalMissing, Dbg(key))
                    })?
                    .send(())
                    .map_err(|_| {
                        error!(ErrorCode::FileTransferScramblerStopFailed, Dbg(key))
                    })?;
                // stop the async task pulling from the async cryptscrambler
                file_transfer
                    .start
                    .ok_or_else(|| {
                        error!(ErrorCode::FileTransferStartSignalMissing, Dbg(key))
                    })?
                    .send(false)
                    .map_err(|_| {
                        error!(ErrorCode::FileTransferScramblerHaltFailed, Dbg(key))
                    })?;
                let _ = self
                    .kernel_tx
                    .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                        message: "The adjacent node did not accept the file transfer request"
                            .into(),
                        ticket_opt: Some(ticket),
                        cid_opt: Some(session_cid),
                    }));
            } else {
                return Err(error!(ErrorCode::FileTransferOutboundMissing, Dbg(key)));
            }
        }

        Ok(())
    }

    /// This tells us that we should burst-send the packets now. Returns false if the UDP sockets disconnected
    /// `to_primary_stream`: If None, will use the Burst Transmitter
    /// `proposed_window`: In TCP only mode, this won't matter since reliability is handled by the TCP layer. As such, in TCP only mode
    /// the tcp sender dispatches ALL packets
    /// NOTE! object ID is in wave_id for header ACKS
    /// NOTE: If object id != 0, then this header ack belongs to a file transfer and must thus be transmitted via TCP
    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn on_group_header_ack_received(
        &self,
        peer_cid: u64,
        group_id: u64,
        object_id: ObjectId,
        next_window: Option<RangeInclusive<u32>>,
        fast_msg: bool,
    ) -> bool {
        let key = GroupKey::new(peer_cid, group_id, object_id);

        if fast_msg {
            let _ = self.outbound_transmitters.remove(&key);
            // we don't proceed past here b/c there's no need to send more data
            return true;
        }

        let mut outbound_container = self.outbound_transmitters.get_mut(&key).unwrap();
        outbound_container.waves_in_current_window = next_window.unwrap_or(0..=0).count();
        // file-transfer, or TCP only mode since next_window is none. Use TCP
        outbound_container
            .burst_transmitter
            .transmit_tcp_file_transfer()
    }

    /// This function is called on Alice's side after Bob sends her a WAVE_ACK.
    /// The purpose of this function, for both tcp_only and reliable-udp, is to free memory.
    /// If using reliable-udp, then then this function has an additional purpose: to keep track
    /// of the number of waves ACK'ed. Once the number of waves ACK'ed equals the window size, this function
    /// also re-engages the transmitter
    #[allow(unused_results)]
    pub fn on_wave_ack_received(
        &mut self,
        session_cid: u64,
        header: &Ref<&[u8], HdpHeader>,
    ) -> bool {
        let object_id = header.context_info.get().into();
        let group = header.group.get();
        let wave_id = header.wave_id.get();
        let target_cid = header.session_cid.get();
        let key = GroupKey::new(target_cid, group, object_id);
        let mut delete_group = false;

        // file transfer
        if let Some(mut transmitter_container) = self.outbound_transmitters.get_mut(&key) {
            // Re-borrow the DashMap `RefMut` as a plain `&mut` so the borrow checker can field-split
            // the container (a `RefMut` derefs as a whole, defeating disjoint-field access below).
            let transmitter_container = &mut *transmitter_container;
            // we set has_begun here instead of the transmit_tcp, simply because we want the first wave to ACK
            transmitter_container.has_begun = true;
            let transmitter = transmitter_container
                .burst_transmitter
                .group_transmitter
                .as_mut()
                .expect("Transmitter not found");
            let relative_group_id = transmitter_container.relative_group_id;
            if transmitter.on_wave_tail_ack_received(wave_id) {
                // Group is finished. Delete it
                let elapsed_sec = transmitter_container
                    .transmission_start_time
                    .elapsed()
                    .as_secs_f32();
                let rate_mb_per_s = (transmitter_container.group_plaintext_length as f32
                    / 1_000_000f32)
                    / elapsed_sec;
                log::trace!(target: "citadel", "Transmitter received final wave ack. Alerting local node to continue transmission of next group");
                // if there is n=1 waves, then the below must be ran. The other use of object notifier in this function only applies for multiple waves
                if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                    let _ = next_group_notifier.unbounded_send(());
                    // alert kernel (transmitter side)
                    log::trace!(target: "citadel", "Notified object sender to begin sending the next group");
                }

                let file_key = FileKey::new(object_id);

                // Clone the sender out of the `DashMap` `Ref` and drop the Ref immediately, so the
                // `file_transfer_handles.remove` calls below can't self-deadlock on the same shard.
                let tx = self
                    .file_transfer_handles
                    .get(&file_key)
                    .map(|r| r.value().clone());
                if let Some(tx) = tx {
                    let status = if relative_group_id as usize
                        != transmitter_container
                            .parent_object_total_groups
                            .saturating_sub(1)
                    {
                        ObjectTransferStatus::TransferTick(
                            relative_group_id as usize,
                            transmitter_container.parent_object_total_groups,
                            rate_mb_per_s,
                        )
                    } else {
                        ObjectTransferStatus::TransferComplete
                    };

                    log::trace!(target: "citadel", "Transmitter {session_cid}: {file_key:?} received final wave ack. Sending status to local node: {status:?}");
                    if let Err(err) = tx.unbounded_send(status.clone()) {
                        // if the server is using an accept-only policy with no further responses, this branch
                        // will be reached
                        log::warn!(target: "citadel", "FileTransfer receiver handle cannot be reached {err:?}");
                        // drop local async sending subroutines
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }

                    if matches!(status, ObjectTransferStatus::TransferComplete) {
                        // remove the transmitter. Dropping will stop related futures
                        log::trace!(target: "citadel", "FileTransfer is complete! Local is server? {}", self.is_server);
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }
                } else {
                    log::error!(target: "citadel", "Unable to find ObjectTransferHandle for {:?} | Local is {session_cid} | FileKeys available: {:?}", file_key, self.file_transfer_handles.iter().map(|r| *r.key()).collect::<Vec<_>>());
                }

                delete_group = true;
            }

            // TODO: The problem with premature loading is that the next group loaded may expire while the current is still transferring
            // even though the next GROUP_HEADER is sent out concurrent to this group transferring. Since file transfers use TCP, the TCP
            // stack may not get to it until after this group is done transferring. By the time that happens, the group on the sender side
            // may have expired. Thus, in order to fix this, we should designate a flag `has_begun`, similar to the receiving side
            if transmitter.is_atleast_fifty_percent_done() {
                if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                    let _ = next_group_notifier.unbounded_send(());
                    log::trace!(target: "citadel", "Notified object sender to begin sending the next group");
                }
            }
        } else {
            log::error!(target: "citadel", "File-transfer for object {object_id} does not map to a transmitter container");
        }

        if delete_group {
            log::trace!(target: "citadel", "Group is done transmitting! Freeing memory ...");
            self.outbound_transmitters.remove(&key);
        }

        true
    }
}
