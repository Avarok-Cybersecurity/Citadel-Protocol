//! Virtual-connection management for [`StateContainerInner`]: creation,
//! lookup, direct-P2P upgrade, and stream selection.

use super::includes::*;
use citadel_io::{error, ErrorCode};

impl<R: Ratchet> StateContainerInner<R> {
    /// Attempts to find the direct p2p stream. If not found, will use the default
    /// to_server stream. Note: the underlying crypto is still the same
    ///
    /// Returns None if neither the peer connection nor the C2S connection exist,
    /// which can happen during shutdown when connections are being torn down.
    pub fn get_preferred_stream(&self, peer_cid: u64) -> Option<&OutboundPrimaryStreamSender> {
        fn get_inner<R: Ratchet>(
            this: &StateContainerInner<R>,
            peer_cid: u64,
        ) -> Option<&OutboundPrimaryStreamSender> {
            Some(
                &this
                    .active_virtual_connections
                    .get(&peer_cid)?
                    .endpoint_container
                    .as_ref()?
                    .direct_p2p_remote
                    .as_ref()?
                    .p2p_primary_stream,
            )
        }

        // Try peer connection first, then fall back to C2S
        get_inner(self, peer_cid).or_else(|| get_inner(self, C2S_IDENTITY_CID))
    }

    /// The inner P2P handles will get dropped, causing the connections to end
    pub fn end_connections(&mut self) {
        self.active_virtual_connections.clear();
    }

    /// In order for the upgrade to work, the peer_addr must be reflective of the peer_addr present when
    /// receiving the packet. As such, the direct p2p-stream MUST have sent the packet
    ///
    /// `implcid`: Local CID for deterministic tie-breaker when simultaneous connections occur.
    /// Pass 0 for C2S connections (no tie-breaking needed).
    ///
    /// `p2p_disconnect_notifier`: Optional oneshot sender for disconnect notification.
    /// When the P2P connection ends, this sender will be triggered, allowing the receiver
    /// to forward the disconnect signal to the kernel. Pass None for C2S connections.
    pub(crate) fn insert_direct_p2p_connection(
        &mut self,
        mut provisional: DirectP2PRemote,
        peer_cid: u64,
        implcid: u64,
        p2p_disconnect_notifier: Option<
            citadel_io::tokio::sync::oneshot::Sender<P2PDisconnectSignal>,
        >,
    ) -> Result<(), NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) {
            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                log::trace!(target: "citadel", "UPGRADING {} conn type", provisional.from_listener.if_eq(true, "listener").if_false("client"));

                // CID-based tie-breaker for simultaneous P2P connections (defense-in-depth).
                // Rule: Keep connection where the higher-CID peer is the client.
                // This ensures both peers converge on the SAME underlying connection.
                if let Some(existing) = endpoint_container.direct_p2p_remote.as_ref() {
                    // Determine which connection type we should have based on CIDs
                    // If implcid < peer_cid, we should be the listener (peer is client)
                    let should_be_listener = implcid != 0 && implcid < peer_cid;

                    if existing.from_listener == should_be_listener {
                        // Existing connection is the correct type, discard provisional
                        log::info!(target: "citadel",
                            "P2P already has correct {} connection for peer {peer_cid}, discarding duplicate {} connection",
                            existing.from_listener.if_eq(true, "listener").if_false("client"),
                            provisional.from_listener.if_eq(true, "listener").if_false("client")
                        );
                        // Stop the provisional's handler cleanly
                        if let Some(stopper) = provisional.stopper.take() {
                            let _ = stopper.send(());
                        }
                        return Ok(());
                    } else if provisional.from_listener == should_be_listener {
                        // Provisional is the correct type, replace existing
                        log::info!(target: "citadel",
                            "Replacing {} with correct {} P2P connection for peer {peer_cid} (CID tie-breaker: implcid={}, peer={})",
                            existing.from_listener.if_eq(true, "listener").if_false("client"),
                            provisional.from_listener.if_eq(true, "listener").if_false("client"),
                            implcid, peer_cid
                        );
                        // Stop the existing handler cleanly before replacing
                        if let Some(mut old) = endpoint_container.direct_p2p_remote.take() {
                            if let Some(stopper) = old.stopper.take() {
                                let _ = stopper.send(());
                            }
                        }
                    } else {
                        // Neither matches expected type (edge case) - keep existing
                        log::warn!(target: "citadel",
                            "Neither connection matches expected type for peer {peer_cid}, keeping existing {} (expected {})",
                            existing.from_listener.if_eq(true, "listener").if_false("client"),
                            should_be_listener.if_eq(true, "listener").if_false("client")
                        );
                        if let Some(stopper) = provisional.stopper.take() {
                            let _ = stopper.send(());
                        }
                        return Ok(());
                    }
                }

                // By setting the below value, all outbound packets will use
                // this direct conn over the proxied TURN-like connection
                vconn.sender = Some((None, provisional.p2p_primary_stream.clone())); // setting this will allow the UDP stream to be upgraded too
                endpoint_container.direct_p2p_remote = Some(provisional);

                // Set the P2P disconnect notifier for bidirectional disconnect propagation (P2P only)
                if let Some(notifier) = p2p_disconnect_notifier {
                    if endpoint_container.p2p_disconnect_notifier.is_some() {
                        log::warn!(target: "citadel", "Replacing existing P2P disconnect notifier for peer {peer_cid}");
                    }
                    endpoint_container.p2p_disconnect_notifier = Some(notifier);
                }

                return Ok(());
            }
        }

        Err(error!(ErrorCode::StateVconnUpgradeFailed))
    }

    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn create_virtual_connection<T: PlatformOps>(
        &mut self,
        default_security_settings: SessionSecuritySettings,
        channel_ticket: Ticket,
        target_cid: u64,
        virtual_connection_type: VirtualConnectionType,
        endpoint_crypto: PeerSessionCrypto<R>,
        sess: &CitadelSession<R, T>,
        file_transfer_compatible: bool,
        p2p_connection_id: Ticket,
    ) -> Result<PeerChannel<R>, NetworkError> {
        let (tx_ratchet_manager_to_outbound, mut rx_from_ratchet_manager_to_outbound) = unbounded();
        let (tx_to_outbound, rx_for_outbound) =
            crate::proto::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS); // Put backpressure on requests
        let (rekey_tx, mut rekey_rx) = tokio::sync::mpsc::unbounded_channel::<R>();
        // Take messages from the ratchet manager , forward it to the dedicated outbound sender
        let task_outbound = async move {
            while let Some(ratchet_layer_message) = rx_from_ratchet_manager_to_outbound.recv().await
            {
                // TODO: Streamline and just send the message here, copying the logic from session.rs where the corresponding
                // SessionRequest is handled in the spawn_message_sender_function near line
                if let Err(err) = tx_to_outbound
                    .send(SessionRequest::SendMessage(ratchet_layer_message))
                    .await
                {
                    citadel_logging::error!(target: "citadel", "Failed to send secure protocol packet for {virtual_connection_type}: {err:?}");
                    break;
                }
            }

            citadel_logging::warn!(target: "citadel", "Outbound ratchet task for {virtual_connection_type} ended");
        };

        let kernel_tx = self.kernel_tx.clone();
        let session_cid = virtual_connection_type.get_session_cid();
        let triggered_rekeys = self.triggered_rekeys.clone();
        // On each rekey finished, take the received ratchet, R, and send it through the kernel_tx
        let task_rekey_finished_listener = async move {
            while let Some(rekey_finished) = rekey_rx.recv().await {
                let mut lock = triggered_rekeys.lock();
                if let Some(entry) = lock.iter().find(|r| r.0.target_cid == target_cid) {
                    let ticket = *entry.1;
                    let to_remove = *entry.0;
                    lock.remove(&to_remove);
                    let result = NodeResult::ReKeyResult(ReKeyResult {
                        ticket,
                        status: ReKeyReturnType::Success {
                            version: rekey_finished.version(),
                        },
                        session_cid,
                    });
                    if let Err(err) = kernel_tx.unbounded_send(result) {
                        citadel_logging::error!(target: "citadel", "Failed to send rekey result for {virtual_connection_type}: {err:?}");
                        break;
                    }
                }
            }
        };

        let password_cid_index = match virtual_connection_type {
            VirtualConnectionType::LocalGroupPeer { .. } => target_cid, // TODO make sure this is right
            VirtualConnectionType::LocalGroupServer { .. } => C2S_IDENTITY_CID,
            _ => {
                panic!("HyperWAN functionality not yet enabled");
            }
        };

        let psks = self
            .get_session_password(password_cid_index)
            .cloned()
            .expect("The PSK was not found!");

        let (tx_to_ratchet_manager_inbound, rx_for_ratchet_manager) = unbounded_channel();

        let ratchet_manager = ProtocolRatchetManager::new(
            Box::new(tx_ratchet_manager_to_outbound),
            Box::new(UnboundedReceiverStream::new(rx_for_ratchet_manager)),
            endpoint_crypto,
            psks.as_ref(),
        );

        let is_active = Arc::new(AtomicBool::new(true));

        let protocol_messenger = ProtocolMessenger::new(
            ratchet_manager.clone(),
            default_security_settings.secrecy_mode,
            Some(rekey_tx),
            is_active.clone(),
        );

        // This will automatically take inbound messages, order them, and forward them to the ratchet manager for processing
        // where the ratchet manager will automatically forward the processed messages to the protocol_messenger above
        let to_channel = OrderedChannel::new(tx_to_ratchet_manager_inbound);

        // We don't need an inbound task since:
        // [*] Inbound messages get passed like usual to the ordered channel (1)
        // [*] The ordered channel passes the message to the ratchet manager (2)
        // [*] the ratchet manager passes to the protocol messenger (3)
        // [*] the protocol messenger gets polled for messages (4)

        let is_server = sess.is_server;

        let combined_task = async move {
            tokio::select! {
                _ = task_rekey_finished_listener => {}
                _ = task_outbound => {}
            };

            citadel_logging::warn!(target: "citadel", "Combined task for {virtual_connection_type} ended (is_server: {is_server})");
        };

        spawn!(combined_task);

        // Build disconnect token for P2P connections
        let disconnect_token = match virtual_connection_type {
            VirtualConnectionType::LocalGroupPeer { session_cid, .. } => Some(DisconnectToken {
                cid: session_cid,
                connection_id: p2p_connection_id,
            }),
            _ => None, // C2S connections don't use P2P disconnect tokens in the channel
        };

        let peer_channel = PeerChannel::new(
            self.node_remote.clone(),
            target_cid,
            virtual_connection_type,
            channel_ticket,
            default_security_settings.security_level,
            is_active.clone(),
            protocol_messenger,
            disconnect_token,
        );

        CitadelSession::spawn_message_sender_function(
            sess.clone(),
            virtual_connection_type,
            rx_for_outbound,
        );

        let endpoint_container = Some(EndpointChannelContainer {
            direct_p2p_remote: None,
            ratchet_manager,
            channel_signal: None,
            to_ordered_local_channel: to_channel,
            to_unordered_local_channel: None,
            file_transfer_compatible,
            // P2P disconnect notifier - set to None initially, will be populated
            // by p2p_conn_handler when P2P stream is established
            p2p_disconnect_notifier: None,
        });

        // For C2S connections, get the adjacent NAT type from the session
        // For P2P connections, this will be updated later during hole punching
        let adjacent_nat_type = (*sess.adjacent_nat_type).clone();

        let vconn = VirtualConnection {
            last_delivered_message_timestamp: DualRwLock::from(None),
            connection_type: virtual_connection_type,
            is_active,
            sender: None,
            endpoint_container,
            adjacent_nat_type,
            p2p_connection_id,
        };

        // Guard: when both peers call connect_to_peer() simultaneously, two independent
        // Kex sequences complete, each calling create_virtual_connection(). The second call
        // would overwrite the first vconn, dropping its ratchet_manager and killing any
        // in-flight operations (e.g., rekey). Skip the insert if an active vconn already
        // exists — the first connection is valid and should be preserved.
        // During reconnect, the old vconn is marked inactive by disconnect processing,
        // so the overwrite proceeds correctly.
        if let Some(existing) = self.active_virtual_connections.get(&target_cid) {
            if existing.is_active.load(Ordering::SeqCst) && existing.endpoint_container.is_some() {
                log::info!(target: "citadel",
                    "Active vconn for peer {target_cid} already exists (simultaneous connect race), \
                     dropping duplicate Kex result");
                // Err so callers skip PeerChannelCreated and hole punch (they treat this as a
                // benign "duplicate suppressed", not a session failure). The new vconn drops here;
                // its Drop calls ratchet_manager.shutdown(), safe — it was never connected to a stream.
                return Err(error!(ErrorCode::StateVconnSimultaneousRace, target_cid));
            }
        }

        // Clear any stale ratchet for this peer — the new connection
        // supersedes it and provides a fresh ratchet via the new vconn.
        self.stale_p2p_ratchets.remove(&target_cid);

        self.active_virtual_connections.insert(target_cid, vconn);

        Ok(peer_channel)
    }

    /// Note: the `endpoint_crypto` container needs to be Some in order for transfer to occur between peers w/o encryption/decryption at the center point
    /// GROUP packets and PEER_CMD::CHANNEL packets bypass the central node's encryption/decryption phase
    pub fn insert_new_virtual_connection_as_server(
        &mut self,
        target_cid: u64,
        connection_type: VirtualConnectionType,
        target_udp_sender: Option<OutboundUdpSender>,
        target_tcp_sender: OutboundPrimaryStreamSender,
    ) {
        let val = VirtualConnection {
            last_delivered_message_timestamp: DualRwLock::from(None),
            endpoint_container: None,
            sender: Some((target_udp_sender, target_tcp_sender)),
            connection_type,
            is_active: Arc::new(AtomicBool::new(true)),
            adjacent_nat_type: None, // Server doesn't have direct NAT info for clients
            p2p_connection_id: Ticket(0), // Server doesn't track P2P connection IDs
        };
        if self
            .active_virtual_connections
            .insert(target_cid, val)
            .is_some()
        {
            log::warn!(target: "citadel", "Inserted a virtual connection. but overwrote one in the process. Report to developers");
        }

        log::trace!(target: "citadel", "Vconn {} -> {} established", connection_type.get_session_cid(), target_cid);
    }

    pub fn get_virtual_connection_crypto(&self, peer_cid: u64) -> Option<&PeerSessionCrypto<R>> {
        Some(
            self.active_virtual_connections
                .get(&peer_cid)?
                .endpoint_container
                .as_ref()?
                .ratchet_manager
                .session_crypto_state(),
        )
    }

    pub fn get_virtual_connection_mut(
        &mut self,
        target_cid: u64,
    ) -> Result<&mut VirtualConnection<R>, NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&target_cid) {
            Ok(vconn)
        } else {
            Err(error!(ErrorCode::StateVconnNotFound, target_cid))
        }
    }

    pub fn get_virtual_connection(
        &self,
        target_cid: u64,
    ) -> Result<&VirtualConnection<R>, NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get(&target_cid) {
            Ok(vconn)
        } else {
            Err(error!(ErrorCode::StateVconnNotFound, target_cid))
        }
    }

    pub fn get_endpoint_container_mut(
        &mut self,
        target_cid: u64,
    ) -> Result<&mut EndpointChannelContainer<R>, NetworkError> {
        let v_conn = self.get_virtual_connection_mut(target_cid)?;
        if let Some(endpoint_container) = v_conn.endpoint_container.as_mut() {
            Ok(endpoint_container)
        } else {
            Err(error!(
                ErrorCode::StateEndpointContainerNotFound,
                target_cid
            ))
        }
    }

    pub fn get_endpoint_container(
        &self,
        target_cid: u64,
    ) -> Result<&EndpointChannelContainer<R>, NetworkError> {
        let v_conn = self.get_virtual_connection(target_cid)?;
        if let Some(endpoint_container) = v_conn.endpoint_container.as_ref() {
            Ok(endpoint_container)
        } else {
            Err(error!(
                ErrorCode::StateEndpointContainerNotFound,
                target_cid
            ))
        }
    }

    pub(super) fn get_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        self.get_virtual_connection(C2S_IDENTITY_CID)
            .ok()?
            .endpoint_container
            .as_ref()?
            .get_direct_p2p_primary_stream()
    }
}
