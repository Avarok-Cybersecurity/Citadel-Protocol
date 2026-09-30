//! Virtual-connection management for [`StateContainerInner`]: creation,
//! lookup, direct-P2P upgrade, and stream selection.

use super::includes::*;
use crate::proto::peer::direct_journal::DirectJournal;
use crate::proto::peer::direct_route;
use crate::proto::peer::p2p_path::P2pPathCell;
use citadel_io::{error, ErrorCode};

/// What happened when a direct route ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RouteEnd {
    /// The route had already been replaced or detached, or the connection is gone.
    NotCurrent,
    /// The connection is closing: tear it down as before.
    ConnectionClosed,
    /// The connection is live and now runs over the server relay.
    FellBack,
}

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
        provisional: DirectP2PRemote,
        peer_cid: u64,
        implcid: u64,
        p2p_disconnect_notifier: Option<
            citadel_io::tokio::sync::oneshot::Sender<P2PDisconnectSignal>,
        >,
    ) -> Result<(), NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) {
            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                let installed = direct_route::attach(
                    &mut endpoint_container.direct_p2p_remote,
                    provisional,
                    implcid,
                    peer_cid,
                    &mut endpoint_container.direct_journal.lock(),
                );
                if !installed {
                    return Ok(());
                }
                // By setting the below value, all outbound packets will use
                // this direct conn over the proxied TURN-like connection
                vconn.sender = endpoint_container
                    .direct_p2p_remote
                    .as_ref()
                    .map(|remote| (None, remote.p2p_primary_stream.clone())); // setting this will allow the UDP stream to be upgraded too

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

    /// The unacknowledged-message journal of `peer_cid`'s direct route, when its traffic runs over
    /// one. `None` on the server relay and for the C2S connection, neither of which needs one.
    pub(crate) fn direct_journal_for(
        &self,
        peer_cid: u64,
    ) -> Option<&citadel_io::Mutex<DirectJournal>> {
        if peer_cid == C2S_IDENTITY_CID {
            return None;
        }
        let endpoint = self
            .active_virtual_connections
            .get(&peer_cid)?
            .endpoint_container
            .as_ref()?;
        endpoint.direct_p2p_remote.as_ref()?;
        Some(&endpoint.direct_journal)
    }

    /// The direct route `route_id` to `peer_cid` ended. When it is still the connection's route
    /// and the connection is live, traffic falls back to the server relay: the route is detached,
    /// every message it had not delivered is re-sent over the relay ahead of anything new, and the
    /// path cell reports [`P2pPath::ServerRelay`](crate::proto::peer::p2p_path::P2pPath) so the
    /// campaign can retry. The channel stays open throughout.
    pub(crate) fn fall_back_to_server_relay(&mut self, peer_cid: u64, route_id: u64) -> RouteEnd {
        let is_current = self
            .active_virtual_connections
            .get(&peer_cid)
            .and_then(|vconn| vconn.endpoint_container.as_ref())
            .and_then(|endpoint| endpoint.direct_p2p_remote.as_ref())
            .is_some_and(|remote| remote.route_id == route_id);
        if !is_current {
            return RouteEnd::NotCurrent;
        }
        let is_active = self
            .active_virtual_connections
            .get(&peer_cid)
            .is_some_and(|vconn| vconn.is_active.load(Ordering::SeqCst));
        if !is_active {
            return RouteEnd::ConnectionClosed;
        }

        self.remove_udp_channel(peer_cid);
        let Some(relay) = self.get_preferred_stream(C2S_IDENTITY_CID).cloned() else {
            return RouteEnd::ConnectionClosed;
        };
        let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) else {
            return RouteEnd::NotCurrent;
        };
        vconn.sender = None;
        let Some(endpoint) = vconn.endpoint_container.as_mut() else {
            return RouteEnd::NotCurrent;
        };
        // Dropping the remote fires its stopper; its handler is already on its way out.
        drop(endpoint.direct_p2p_remote.take());
        let resent = endpoint.direct_journal.lock().drain_onto(&relay);
        endpoint.p2p_path.fall_back_to_server_relay();
        log::warn!(target: "citadel", "Direct route to peer {peer_cid} ended; fell back to the server relay and re-sent {resent} unacknowledged message(s)");
        // Transfers are NOT failed here: C2S is up, so a transfer's completion (its final ack
        // travels over C2S) can still arrive, and failing on the direct stream's end used to beat
        // it. A transfer that really stalls ends by its own group timeouts, or by the Disconnect
        // rebound if the connection itself ends.
        RouteEnd::FellBack
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
                // An exact lookup, not a scan. The scan matched on target_cid
                // and took whichever entry hash order produced, so with more
                // than one entry for a CID -- which a leaked failure made
                // ordinary -- a success could be reported against the wrong
                // ticket.
                if let Some(ticket) = lock.remove(&target_cid) {
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

        let p2p_path = P2pPathCell::server_relayed();
        let peer_channel = PeerChannel::new(
            self.node_remote.clone(),
            target_cid,
            virtual_connection_type,
            channel_ticket,
            default_security_settings.security_level,
            is_active.clone(),
            protocol_messenger,
            disconnect_token,
            p2p_path.clone(),
        );

        CitadelSession::spawn_message_sender_function(
            sess.clone(),
            virtual_connection_type,
            rx_for_outbound,
        );

        let endpoint_container = Some(EndpointChannelContainer {
            direct_p2p_remote: None,
            p2p_path,
            direct_journal: Default::default(),
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
            // Client side: this node never runs the server's peer teardown, so
            // there is no incarnation question to answer here.
            peer_session_init_time: None,
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
    /// `peer_session_init_time` identifies WHICH incarnation of `target_cid`'s
    /// session this vConn was forged with -- see the field. The server holds
    /// both sessions at the moment it forges the pair, so it is the only place
    /// that can answer it.
    pub fn insert_new_virtual_connection_as_server(
        &mut self,
        target_cid: u64,
        connection_type: VirtualConnectionType,
        target_udp_sender: Option<OutboundUdpSender>,
        target_tcp_sender: OutboundPrimaryStreamSender,
        peer_session_init_time: Instant,
    ) {
        let val = VirtualConnection {
            last_delivered_message_timestamp: DualRwLock::from(None),
            endpoint_container: None,
            sender: Some((target_udp_sender, target_tcp_sender)),
            connection_type,
            is_active: Arc::new(AtomicBool::new(true)),
            adjacent_nat_type: None, // Server doesn't have direct NAT info for clients
            p2p_connection_id: Ticket(0), // Server doesn't track P2P connection IDs
            peer_session_init_time: Some(peer_session_init_time),
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
