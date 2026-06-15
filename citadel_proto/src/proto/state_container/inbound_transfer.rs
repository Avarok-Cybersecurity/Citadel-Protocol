//! Inbound group/file reception for [`StateContainerInner`]: group-header and
//! file-header intake plus per-wave payload reassembly.

use super::includes::*;

impl<R: Ratchet> StateContainerInner<R> {
    /// Like the other functions in this file, ensure that verification is called before running this
    /// Returns the initial wave window
    #[allow(unused_results)]
    pub fn on_group_header_received(
        &mut self,
        header: &Ref<&[u8], HdpHeader>,
        group_receiver_config: GroupReceiverConfig,
        virtual_target: VirtualTargetType,
    ) -> Result<RangeInclusive<u32>, NetworkError> {
        log::trace!(target: "citadel", "GRC config: {group_receiver_config:?}");
        let object_id = group_receiver_config.object_id;
        let group_id = header.group.get();
        let ticket = header.context_info.get();
        // below, the target_cid in the key is where the packet came from. If it is a client, or a hyperlan conn, the implicated cid stays the same
        let inbound_group_key = GroupKey::new(header.session_cid.get(), group_id, object_id);
        if let dashmap::mapref::entry::Entry::Vacant(e) =
            self.inbound_groups.entry(inbound_group_key)
        {
            let receiver = GroupReceiver::new(
                group_receiver_config,
                INDIVIDUAL_WAVE_TIMEOUT_MS,
                GROUP_TIMEOUT_MS,
            );
            let security_level = SecurityLevel::for_value(header.security_level as usize)
                .ok_or_else(|| {
                    NetworkError::msg(format!(
                        "Invalid security level {} in group header",
                        header.security_level
                    ))
                })?;
            let mut receiver_container = GroupReceiverContainer::new(
                object_id,
                receiver,
                virtual_target,
                security_level,
                ticket.into(),
            );
            // check to see if we need to copy the last wave window
            let last_window_size = if object_id != ObjectId::zero() {
                // copy previous window
                let file_key = FileKey::new(object_id);
                if let Some(inbound_file_transfer) = self.inbound_files.get(&file_key) {
                    inbound_file_transfer.last_group_window_len
                } else {
                    return Err(NetworkError::msg(format!(
                        "The GROUP HEADER implied a file transfer, but key {file_key:?} maps to nothing"
                    )));
                }
            } else {
                0
            };

            let wave_window = if last_window_size != 0 {
                // the last_window_size may not have an oversized length. take the min
                receiver_container.last_window_size = last_window_size;
                let waves_in_group = receiver_container.receiver.get_wave_count();
                // take waves_in_group - 1 because it needs to take into account the max inclusive boundary
                let max_idx =
                    std::cmp::min(last_window_size, waves_in_group.saturating_sub(1)) as u32;
                let min_idx = 0; // this is a new group; start at zero
                receiver_container.current_window = min_idx..=max_idx;
                min_idx..=max_idx
            } else {
                // if it was zero, not part of a file. Use the one proposed by the receiver container, by default
                receiver_container.current_window.clone()
            };

            e.insert(receiver_container);
            Ok(wave_window)
        } else {
            Err(NetworkError::msg(format!(
                "Duplicate group HEADER detected ({group_id})"
            )))
        }
    }

    /// This creates an entry in the inbound_files hashmap
    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn on_file_header_received(
        &mut self,
        header: &Ref<&[u8], HdpHeader>,
        virtual_target: VirtualTargetType,
        metadata_orig: VirtualObjectMetadata,
        pers: &PersistenceHandler<R, R>,
        state_container: StateContainer<R>,
        ratchet: R,
        _target_cid: u64,
        v_target_flipped: VirtualTargetType,
        preferred_primary_stream: OutboundPrimaryStreamSender,
        local_encryption_level: Option<SecurityLevel>,
    ) -> bool {
        let target_cid = v_target_flipped.get_target_cid();
        let session_cid = v_target_flipped.get_session_cid();
        let object_id = metadata_orig.object_id;

        let key = FileKey::new(object_id);
        let ticket = header.context_info.get().into();
        let is_revfs_pull = local_encryption_level.is_some();

        log::trace!(target: "citadel", "File header {session_cid}: {key:?} | revfs_pull: {is_revfs_pull}");

        if let dashmap::mapref::entry::Entry::Vacant(e) = self.inbound_files.entry(key) {
            let (stream_to_hd, stream_to_hd_rx) = unbounded::<Vec<u8>>();

            let security_level_rebound: SecurityLevel = header.security_level.into();
            let timestamp = self.time_tracker.get_global_time_ns();
            let pers = pers.clone();
            let metadata = metadata_orig.clone();
            let tt = self.time_tracker;
            let (reception_complete_tx, success_receiving_rx) =
                citadel_io::tokio::sync::oneshot::channel();
            let entry = InboundFileTransfer {
                last_group_finish_time: tt.get_global_time_ns(),
                last_group_window_len: 0,
                object_id,
                total_groups: metadata_orig.group_count,
                ticket,
                groups_rendered: 0,
                virtual_target,
                metadata: metadata.clone(),
                reception_complete_tx,
                stream_to_hd,
                local_encryption_level,
            };

            let (start_recv_tx, start_recv_rx) = if !is_revfs_pull {
                let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };

            e.insert(entry);
            let (handle, tx_status) = ObjectTransferHandler::new(
                target_cid,
                session_cid,
                metadata.clone(),
                ObjectTransferOrientation::Receiver { is_revfs_pull },
                start_recv_tx,
            );
            self.file_transfer_handles
                .insert(key, UnboundedSender(tx_status.clone()));
            // finally, alert the kernel (receiver)
            if let Err(err) = self
                .kernel_tx
                .unbounded_send(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                    ticket,
                    handle,
                    session_cid,
                }))
            {
                log::error!(target: "citadel", "Failed to send the ObjectTransferHandle to the kernel: {err:?}");
            }

            let is_server = self.is_server;

            let task = async move {
                log::debug!(target: "citadel", "File transfer initiated, awaiting acceptance ... | revfs_pull: {is_revfs_pull}");
                let res = if let Some(start_rx) = start_recv_rx {
                    start_rx.await
                } else {
                    Ok(true)
                };

                log::debug!(target: "citadel", "File transfer initiated! | revfs_pull: {is_revfs_pull}");

                let accepted = res.as_ref().map(|r| *r).unwrap_or(false);
                // first, send a rebound signal immediately to the sender
                // to ensure the sender knows if the user accepted or not
                let file_header_ack = packet_crafter::file::craft_file_header_ack_packet(
                    &ratchet,
                    accepted,
                    object_id,
                    target_cid,
                    ticket,
                    security_level_rebound,
                    v_target_flipped,
                    timestamp,
                    metadata_orig.transfer_type.clone(),
                );

                if let Err(err) = preferred_primary_stream.unbounded_send(file_header_ack) {
                    log::error!(target: "citadel", "Unable to send file_header_ack rebound signal; aborting: {err:?}");
                    return;
                }

                match res {
                    Ok(accepted) => {
                        if accepted {
                            // local user accepts the file transfer. Alert the adjacent end
                            // and get ready to begin streaming
                            match pers
                                .stream_object_to_backend(
                                    stream_to_hd_rx,
                                    &metadata,
                                    tx_status.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    // TODO: Consider adding a function that waits for the actual file size to be equal to the metadata plaintext length
                                    // in order to not allow the kernel logic to prematurely read the file contents while still syncing.
                                    log::info!(target: "citadel", "Successfully synced file to backend | revfs_pull: {is_revfs_pull} | is_server: {is_server}");
                                    let status = match success_receiving_rx.await {
                                        Ok(header) => {
                                            // write the header
                                            let wave_ack = packet_crafter::group::craft_wave_ack(
                                                &ratchet,
                                                object_id,
                                                get_resp_target_cid_from_header(&header),
                                                header.group.get(),
                                                header.wave_id.get(),
                                                tt.get_global_time_ns(),
                                                None,
                                                header.security_level.into(),
                                            );

                                            send_with_error_logging(
                                                &preferred_primary_stream,
                                                wave_ack,
                                            );

                                            ObjectTransferStatus::ReceptionComplete
                                        }

                                        Err(_) => ObjectTransferStatus::Fail(
                                            "An unknown error occurred while receiving file"
                                                .to_string(),
                                        ),
                                    };

                                    if let Err(err) = tx_status.send(status) {
                                        log::error!(target: "citadel", "Unable to send object transfer status to handle: {err:?}");
                                    }
                                }
                                Err(err) => {
                                    log::error!(target: "citadel", "Unable to sync file to backend: {err:?}");
                                }
                            }
                        } else {
                            if let Err(err) = tx_status.send(ObjectTransferStatus::Fail(
                                "User did not accept file transfer".to_string(),
                            )) {
                                log::error!(target: "citadel", "Unable to send object transfer status to handle: {err:?}");
                            }
                            // user did not accept. cleanup local (DashMap removes need only a read lock)
                            log::warn!(target: "citadel", "User did not accept file transfer");
                            let state_container = inner_state!(state_container);
                            let _ = state_container.inbound_files.remove(&key);
                            let _ = state_container.file_transfer_handles.remove(&key);
                        }
                    }

                    Err(err) => {
                        log::error!(target: "citadel", "Start_recv_rx failed: {err:?}");
                        let err_packet = packet_crafter::file::craft_file_header_ack_packet(
                            &ratchet,
                            false,
                            object_id,
                            target_cid,
                            ticket,
                            security_level_rebound,
                            virtual_target,
                            timestamp,
                            metadata_orig.transfer_type.clone(),
                        );
                        let _ = preferred_primary_stream.unbounded_send(err_packet);
                    }
                }
            };

            spawn!(task);
            true
        } else {
            log::error!(target: "citadel", "Duplicate file HEADER detected");
            false
        }
    }

    pub fn on_group_payload_received(
        &self,
        header: &HdpHeader,
        payload: Bytes,
        hr: &R,
    ) -> Result<PrimaryProcessorResult, (NetworkError, Ticket, ObjectId)> {
        let target_cid = header.session_cid.get();
        let group_id = header.group.get();
        let object_id = header.context_info.get().into();
        let group_key = GroupKey::new(target_cid, group_id, object_id);
        let ts = self.time_tracker.get_global_time_ns();

        // Phase 1: feed the wave into its group receiver under a SCOPED `inbound_groups` RefMut. The
        // RefMut is dropped at the end of this block — BEFORE any `inbound_groups.remove` below — so the
        // `DashMap` shard can't self-deadlock (remove needs the write lock the RefMut holds). Per-group
        // reassembly stays serialized: a concurrent payload for the same `group_key` blocks on this
        // `get_mut` until we release it.
        let (status, ticket, file_key) = {
            let mut grc = self.inbound_groups.get_mut(&group_key).ok_or_else(|| {
                (
                    NetworkError::msg(format!(
                        "inbound_groups does not contain key for {group_key:?}"
                    )),
                    Ticket(0),
                    0.into(),
                )
            })?;
            let ticket = grc.ticket;
            let file_key = FileKey::new(grc.object_id);

            let src = *payload.first().ok_or((
                NetworkError::InvalidRequest("Bad payload packet [0]"),
                ticket,
                object_id,
            ))?;
            let dest = *payload.get(1).ok_or((
                NetworkError::InvalidRequest("Bad payload packet [1]"),
                ticket,
                object_id,
            ))?;

            let true_sequence = citadel_crypt::packet_vector::generate_packet_coordinates_inv(
                header.wave_id.get(),
                src as u16,
                dest as u16,
                hr.get_scramble_pqc_and_entropy_bank().1,
            )
            .ok_or((
                NetworkError::InvalidRequest("Unable to obtain true_sequence"),
                ticket,
                object_id,
            ))?;

            let status = grc.receiver.on_packet_received(
                group_id,
                true_sequence,
                header.wave_id.get(),
                hr,
                &payload[2..],
            );
            (status, ticket, file_key)
        };

        let mut send_wave_ack = false;
        let mut complete = false;

        match status {
            GroupReceiverStatus::GROUP_COMPLETE(_last_wid) => {
                // `grc` is released above → safe to remove + finalize the group.
                let receiver = self
                    .inbound_groups
                    .remove(&group_key)
                    .ok_or_else(|| {
                        (
                            NetworkError::msg(format!(
                                "inbound_groups vanished for {group_key:?} on complete"
                            )),
                            ticket,
                            object_id,
                        )
                    })?
                    .1
                    .receiver;
                let mut chunk = receiver.finalize();
                let bytes_in_group = chunk.len();

                // Snapshot the fields we need from the inbound-file entry, then release the `Ref` so the
                // `inbound_files.remove` below cannot self-deadlock. `stream_to_hd` is an
                // `UnboundedSender` — cheap to clone.
                let (
                    stream_to_hd,
                    total_groups,
                    plaintext_length,
                    local_encryption_level,
                    last_group_finish_time,
                ) = {
                    let fc = self.inbound_files.get(&file_key).ok_or_else(|| {
                        (
                            NetworkError::msg(format!(
                                "inbound_files does not contain key for {file_key:?}"
                            )),
                            ticket,
                            object_id,
                        )
                    })?;
                    (
                        fc.stream_to_hd.clone(),
                        fc.total_groups,
                        fc.metadata.plaintext_length,
                        fc.local_encryption_level,
                        fc.last_group_finish_time,
                    )
                };

                log::trace!(target: "citadel", "GROUP {} COMPLETE. Total groups: {} | Plaintext len: {} | Received plaintext len: {}", group_id, total_groups, plaintext_length, chunk.len());

                if let Some(local_encryption_level) = local_encryption_level {
                    log::trace!(target: "citadel", "Detected REVFS. Locally decrypting object {object_id} with level {local_encryption_level:?} | Ratchet used: {} w/version {}", hr.get_cid(), hr.version());
                    // which static hr do we need? Since we are receiving this chunk, always our local account's
                    let static_aux_hr = self.cnac.as_ref().unwrap().get_static_auxiliary_ratchet();

                    chunk = static_aux_hr
                        .local_decrypt(chunk, local_encryption_level)
                        .map_err(|err| (NetworkError::msg(err.into_string()), ticket, object_id))?;
                }

                stream_to_hd
                    .unbounded_send(chunk)
                    .map_err(|err| (NetworkError::Generic(err.to_string()), ticket, object_id))?;

                send_wave_ack = true;

                if group_id as usize >= total_groups.saturating_sub(1) {
                    complete = true;
                    let file_container = self
                        .inbound_files
                        .remove(&file_key)
                        .ok_or_else(|| {
                            (
                                NetworkError::msg("inbound_files vanished on complete"),
                                ticket,
                                object_id,
                            )
                        })?
                        .1;
                    // status of reception complete now located where the streaming to HD completes
                    // we need only take the sender and send a signal to prove that we finished correctly here
                    // TODO: it seems to be sending the file before the backend streamer even gets a chance to finish
                    // TODO: Do not send the reception complete tx until after the backend streamer has finished
                    file_container
                        .reception_complete_tx
                        .send(header.clone())
                        .map_err(|_| {
                            (
                                NetworkError::msg("reception_complete_tx err"),
                                ticket,
                                object_id,
                            )
                        })?;
                } else {
                    let now = self.time_tracker.get_global_time_ns();
                    let elapsed_nanos = now.saturating_sub(last_group_finish_time) as f64;
                    let bytes_per_ns = bytes_in_group as f64 / elapsed_nanos; // unit: bytes/ns
                                                                              // convert bytes per period into MB/s
                    let mb_per_sec = bytes_per_ns * 1_000_000_000f64; // unit: bytes/sec
                    let mb_per_sec = mb_per_sec / 1_000_000f64; // unit: MB/sec
                                                                // Only use 2 decimals
                    let mb_per_sec = (mb_per_sec * 100.0).round() / 100.0;
                    log::trace!(target: "citadel", "Sending reception tick for group {} of {} | {} MB/s", group_id, total_groups, mb_per_sec);

                    // Write the timestamp back via a fresh scoped `get_mut` (no Ref held across a remove).
                    if let Some(mut fc) = self.inbound_files.get_mut(&file_key) {
                        fc.last_group_finish_time = now;
                    }
                    let status = ObjectTransferStatus::ReceptionTick(
                        group_id as usize,
                        total_groups,
                        mb_per_sec as f32,
                    );
                    // sending the wave ack will complete the group on the initiator side. Tolerate a
                    // missing handle (progress channel torn down) — it must not fail reassembly.
                    if let Some(handle) = self.file_transfer_handles.get(&file_key) {
                        handle.unbounded_send(status).map_err(|err| {
                            (NetworkError::Generic(err.to_string()), ticket, object_id)
                        })?;
                    }
                }
            }

            // common case
            GroupReceiverStatus::INSERT_SUCCESS => {}

            GroupReceiverStatus::WAVE_COMPLETE(..) => {
                // send wave ACK to update progress on adjacent node
                send_wave_ack = true;
            }

            res => {
                log::error!(target: "citadel", "INVALID GroupReceiverStatus obtained: {res:?}")
            }
        }

        if complete {
            log::trace!(target: "citadel", "Finished receiving file {file_key:?}");
            let _ = self.inbound_files.remove(&file_key);
            let _ = self.file_transfer_handles.remove(&file_key);
        }

        if send_wave_ack {
            // only send a wave ack if incomplete, since the backend sync will send it
            if !complete {
                let wave_ack = packet_crafter::group::craft_wave_ack(
                    hr,
                    header.context_info.get().into(),
                    get_resp_target_cid_from_header(header),
                    header.group.get(),
                    header.wave_id.get(),
                    ts,
                    None,
                    header.security_level.into(),
                );
                return Ok(PrimaryProcessorResult::ReplyToSender(wave_ack));
            }
        }

        Ok(PrimaryProcessorResult::Void)
    }
}
