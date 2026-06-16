//! Rekey initiation and group-broadcast handling for [`StateContainerInner`].

use super::includes::*;
use citadel_io::{error, ErrorCode};
use citadel_types::proto::GroupHierarchyMode;

impl<R: Ratchet> StateContainerInner<R> {
    #[allow(unused_results)]
    pub(crate) fn initiate_rekey(
        &mut self,
        virtual_target: VirtualTargetType,
        ticket: Option<Ticket>,
    ) -> Result<(), NetworkError> {
        fn return_already_in_progress<R: Ratchet>(
            kernel_tx: &UnboundedSender<NodeResult<R>>,
            ticket: Ticket,
            session_cid: u64,
        ) -> Result<(), NetworkError> {
            kernel_tx
                .unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status: ReKeyReturnType::AlreadyInProgress,
                    session_cid,
                }))
                .map_err(|err| NetworkError::generic(err.to_string()))
        }

        let ticket = ticket.unwrap_or_default();

        if !self.state.is_connected() {
            return Err(error!(ErrorCode::StateRekeyNotConnected));
        }

        let (session_cid, target_cid) = match virtual_target {
            VirtualConnectionType::LocalGroupServer { session_cid } => {
                (session_cid, C2S_IDENTITY_CID)
            }

            VirtualConnectionType::LocalGroupPeer {
                peer_cid,
                session_cid,
            } => (session_cid, peer_cid),

            _ => return Err(error!(ErrorCode::StateExternalGroupNotImplemented)),
        };

        let v_conn = self.get_endpoint_container(target_cid)?;
        if v_conn.ratchet_manager.is_rekeying() {
            return return_already_in_progress(&self.kernel_tx, ticket, session_cid);
        }

        // Insert into map
        let index = ReKeyIndex { ticket, target_cid };

        if self.triggered_rekeys.lock().insert(index, ticket).is_some() {
            return return_already_in_progress(&self.kernel_tx, ticket, session_cid);
        }

        let to_kernel = self.kernel_tx.clone();

        let ratchet_manager = v_conn.ratchet_manager.clone();
        let task = async move {
            if let Err(err) = ratchet_manager.trigger_rekey(true).await {
                if let Err(err) = to_kernel.unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status: ReKeyReturnType::Failure { err },
                    session_cid,
                })) {
                    log::error!(target: "citadel", "Unable to send ReKeyResult to kernel: {err}");
                }
            }
        };

        spawn!(task);

        Ok(())
    }

    pub(crate) fn process_outbound_broadcast_command(
        &mut self,
        ticket: Ticket,
        command: &GroupBroadcast,
    ) -> Result<(), NetworkError> {
        if !self.state.is_connected() {
            log::warn!(target: "citadel", "Unable to execute group command since session is not connected");
            return Ok(());
        }

        let ratchet = self
            .get_virtual_connection_crypto(C2S_IDENTITY_CID)
            .ok_or(error!(ErrorCode::StateC2sNotLoaded))?
            .get_ratchet(None)
            .unwrap();
        let security_level = self
            .session_security_settings
            .map(|r| r.security_level)
            .unwrap();
        // Cloned (owned) so the `&self` borrow is released before the CGKA `&mut self` encryption below.
        let to_primary_stream = self.get_primary_stream().unwrap().clone();

        let timestamp = self.time_tracker.get_global_time_ns();

        // Owner-local hierarchy admin: Promote/Demote never leave the node as themselves — they produce
        // sealed `HierarchyAssign` (+ a `Commit` for demote) and return here.
        if let GroupBroadcast::Promote {
            key,
            target_cid,
            path,
        } = command
        {
            return self.outbound_promote(
                *key,
                *target_cid,
                path.clone(),
                &ratchet,
                ticket,
                timestamp,
                security_level,
                &to_primary_stream,
            );
        }
        if let GroupBroadcast::Demote { key, target_cid } = command {
            return self.outbound_demote(
                *key,
                *target_cid,
                &ratchet,
                ticket,
                timestamp,
                security_level,
                &to_primary_stream,
            );
        }

        // Rewrite the outbound command where needed: E2E-encrypt an application `Message`, or found the
        // owner's CGKA at `Create` and strip command paths from the relayed copy (zero-trust metadata).
        let replacement: Option<GroupBroadcast> = match command {
            GroupBroadcast::Message {
                sender,
                key,
                message,
            } => {
                let cgka = self
                    .group_cgka
                    .get_mut(key)
                    .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
                let ciphertext = cgka.encrypt_message(message.as_ref())?;
                Some(GroupBroadcast::Message {
                    sender: *sender,
                    key: *key,
                    message: citadel_types::crypto::SecBuffer::from(ciphertext),
                })
            }
            GroupBroadcast::Create {
                initial_invitees,
                options,
            } => {
                self.init_owner_cgka(options)?;
                if matches!(options.hierarchy, GroupHierarchyMode::Flat) {
                    None
                } else {
                    let mut wire_options = options.clone();
                    wire_options.hierarchy = GroupHierarchyMode::Flat;
                    Some(GroupBroadcast::Create {
                        initial_invitees: initial_invitees.clone(),
                        options: wire_options,
                    })
                }
            }
            _ => None,
        };
        let command = replacement.as_ref().unwrap_or(command);

        let packet = match command {
            GroupBroadcast::Create { .. }
            | GroupBroadcast::End { .. }
            | GroupBroadcast::Kick { .. }
            | GroupBroadcast::Message { .. }
            | GroupBroadcast::Add { .. }
            | GroupBroadcast::AcceptMembership { .. }
            | GroupBroadcast::DeclineMembership { .. }
            | GroupBroadcast::RequestJoin { .. }
            | GroupBroadcast::ListGroupsFor { .. }
            | GroupBroadcast::LeaveRoom { .. } => {
                packet_crafter::peer_cmd::craft_group_message_packet(
                    &ratchet,
                    command,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                )
            }

            n => {
                return Err(error!(
                    ErrorCode::StateInvalidGroupBroadcastRequest,
                    format!("{:?}", &n)
                ));
            }
        };

        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::generic(err.to_string()))?;

        // Owner-side membership removal: a Kick also re-keys the group (post-compromise security), so
        // a kicked member cannot read future traffic. Emit a remove `Commit` per kicked member, sent
        // after the Kick itself so the relay drops them from the roster before fanning the Commit out.
        if let GroupBroadcast::Kick { key, kick_list } = command {
            for &cid in kick_list {
                let removed = match self.group_cgka.get_mut(key) {
                    Some(cgka) => cgka.remove_member_by_cid(cid)?,
                    None => None,
                };
                if let Some((commit_bytes, epoch)) = removed {
                    let signal = GroupBroadcast::Commit {
                        key: *key,
                        epoch,
                        payload: commit_bytes,
                    };
                    let commit_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                        &ratchet,
                        &signal,
                        ticket,
                        C2S_IDENTITY_CID,
                        timestamp,
                        security_level,
                    );
                    to_primary_stream
                        .unbounded_send(commit_packet)
                        .map_err(|err| NetworkError::generic(err.to_string()))?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn setup_group_channel_endpoints<T: PlatformOps>(
        &mut self,
        key: MessageGroupKey,
        ticket: Ticket,
        session: &CitadelSession<R, T>,
    ) -> Result<GroupChannel, NetworkError> {
        let (tx, rx) = unbounded();
        let session_cid = self
            .cnac
            .as_ref()
            .map(|r| r.get_cid())
            .ok_or(error!(ErrorCode::StateCnacNotLoaded))?;

        if self.group_channels.contains_key(&key) {
            return Err(error!(ErrorCode::StateGroupChannelExists));
        }

        let _ = self.group_channels.insert(key, tx);

        let (to_session_tx, to_session_rx) =
            crate::proto::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);

        let v_conn_type = VirtualConnectionType::LocalGroupServer { session_cid };

        CitadelSession::spawn_message_sender_function(session.clone(), v_conn_type, to_session_rx);

        Ok(GroupChannel::new(
            to_session_tx,
            key,
            ticket,
            session_cid,
            rx,
        ))
    }
}
