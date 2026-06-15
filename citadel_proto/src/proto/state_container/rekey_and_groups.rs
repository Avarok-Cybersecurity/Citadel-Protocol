//! Rekey initiation and group-broadcast handling for [`StateContainerInner`].

use super::includes::*;

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
            return Err(NetworkError::invalid_request(
                "Cannot initiate rekey since the session is not connected",
            ));
        }

        let (session_cid, target_cid) = match virtual_target {
            VirtualConnectionType::LocalGroupServer { session_cid } => {
                (session_cid, C2S_IDENTITY_CID)
            }

            VirtualConnectionType::LocalGroupPeer {
                peer_cid,
                session_cid,
            } => (session_cid, peer_cid),

            _ => {
                return Err(NetworkError::invalid_request(
                    "External group functionality not yet implemented",
                ))
            }
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
        &self,
        ticket: Ticket,
        command: &GroupBroadcast,
    ) -> Result<(), NetworkError> {
        if !self.state.is_connected() {
            log::warn!(target: "citadel", "Unable to execute group command since session is not connected");
            return Ok(());
        }

        let ratchet = self
            .get_virtual_connection_crypto(C2S_IDENTITY_CID)
            .ok_or(NetworkError::internal("C2s not loaded"))?
            .get_ratchet(None)
            .unwrap();
        let security_level = self
            .session_security_settings
            .map(|r| r.security_level)
            .unwrap();
        let to_primary_stream = self.get_primary_stream().unwrap();

        let timestamp = self.time_tracker.get_global_time_ns();
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
                return Err(NetworkError::generic(format!(
                    "{:?} is not a valid group broadcast request",
                    &n
                )));
            }
        };

        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::generic(err.to_string()))
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
            .ok_or(NetworkError::internal("CNAC not loaded"))?;

        if self.group_channels.contains_key(&key) {
            return Err(NetworkError::internal(
                "Group channel already exists locally",
            ));
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
