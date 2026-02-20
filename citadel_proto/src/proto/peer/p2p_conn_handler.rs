/*!
# P2P Connection Handler Module

This module implements direct peer-to-peer connection handling and NAT traversal functionality for the Citadel Protocol, enabling secure direct connections between peers.

## Features
- **Direct P2P Connections**: Manages direct peer-to-peer connections with support for both TCP and UDP
- **NAT Traversal**: Implements UDP hole punching for NAT traversal
- **Connection Management**: Handles connection setup, teardown, and error recovery
- **WebRTC Support**: Compatible with WebRTC for web-based peer connections
- **Security**: Integrates with Citadel's security infrastructure for encrypted communications

## Core Components
- `DirectP2PRemote`: Manages direct P2P connection state and lifecycle
- `P2PInboundHandle`: Handles incoming P2P connections and related state
- `attempt_simultaneous_hole_punch`: Implements NAT traversal via UDP hole punching
- `PeerNatInfo`: Handles NAT detection and compatibility checking

## Important Notes
1. Supports both TCP and UDP connections with automatic fallback
2. Implements symmetric NAT traversal through coordinated hole punching
3. Handles connection cleanup and resource management
4. Integrates with Citadel's session and security infrastructure

## Related Components
- `peer_layer`: High-level peer networking abstraction
- `peer_crypt`: Handles peer-to-peer encryption
- `session`: Manages connection sessions
- `state_container`: Tracks connection state

*/

use citadel_io::tokio::sync::oneshot::{channel, Receiver, Sender};
use citadel_io::tokio_stream::StreamExt;

use crate::error::NetworkError;
use crate::functional::IfTrueConditional;
use crate::proto::misc;
use crate::proto::misc::dual_rwlock::DualRwLock;
#[cfg(not(target_family = "wasm"))]
use crate::proto::misc::net::{GenericNetworkListener, GenericNetworkStream};
#[cfg(not(target_family = "wasm"))]
use crate::proto::misc::udp_internal_interface::{QuicUdpSocketConnector, UdpSplittableTypes};
use crate::proto::node_result::{NodeResult, PeerEvent};
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::outbound_sender::{unbounded, OutboundPrimaryStreamReceiver, UnboundedSender};
use crate::proto::packet::HeaderObfuscator;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::includes::{Duration, Instant, SocketAddr};
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::remote::Ticket;
use crate::proto::session::{CitadelSession, SessionAliveTracker};
use crate::proto::state_container::{P2PDisconnectSignal, VirtualConnectionType};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::ProtocolIO;
use citadel_types::crypto::SecurityLevel;
use citadel_types::prelude::{SessionSecuritySettings, UdpMode};
#[cfg(not(target_family = "wasm"))]
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
#[cfg(not(target_family = "wasm"))]
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
#[cfg(not(target_family = "wasm"))]
use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::sync::Arc;

pub struct DirectP2PRemote {
    // immediately causes connection to end
    pub(crate) stopper: Option<Sender<()>>,
    pub p2p_primary_stream: OutboundPrimaryStreamSender,
    pub from_listener: bool,
}

impl Debug for DirectP2PRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectP2PRemote")
            .field("from_listener", &self.from_listener)
            .finish()
    }
}

impl DirectP2PRemote {
    /// - quic_connector should be Some for server conns, None for clients
    fn new(
        stopper: Sender<()>,
        p2p_primary_stream: OutboundPrimaryStreamSender,
        from_listener: bool,
    ) -> Self {
        Self {
            stopper: Some(stopper),
            p2p_primary_stream,
            from_listener,
        }
    }
}

impl Drop for DirectP2PRemote {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "[DirectP2PRemote] dropping p2p connection (type: {})...", self.from_listener.if_true("listener").if_false("client"));
        if let Some(stopper) = self.stopper.take() {
            if stopper.send(()).is_err() {
                //log::error!(target: "citadel", "Unable to alert p2p-stopper")
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[allow(clippy::too_many_arguments)]
async fn p2p_conn_handler<R: Ratchet, T: ProtocolIO>(
    mut p2p_listener: GenericNetworkListener,
    session: CitadelSession<R, T>,
    _necessary_remote_addr: SocketAddr,
    v_conn: VirtualConnectionType,
    hole_punched_addr: TargettedSocketAddr,
    ticket: Ticket,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
) -> Result<(), NetworkError> {
    let kernel_tx = session.kernel_tx.clone();
    let session_cid = session.session_cid.clone();
    let weak = &session.as_weak();

    std::mem::drop(session);

    log::trace!(target: "citadel", "[P2P-stream] Beginning async p2p listener subroutine on {:?}", p2p_listener.local_addr().unwrap());

    match p2p_listener.next().await {
        Some(Ok((p2p_stream, _))) => {
            let session = CitadelSession::upgrade_weak(weak)
                .ok_or(NetworkError::InternalError("P2P Session dropped"))?;

            handle_p2p_stream(
                p2p_stream,
                session_cid,
                session,
                kernel_tx,
                true,
                v_conn,
                hole_punched_addr,
                ticket,
                udp_mode,
                session_security_settings,
            )?;
            Ok(())
        }

        Some(Err(err)) => {
            // on android/ios, when the program is backgrounded for days then turned on, this error will loop endlessly. As such, drop this future and end the session to give the program the chance to create a session anew
            //const ERR_INVALID_ARGUMENT: i32 = 22;
            log::error!(target: "citadel", "[P2P-stream] ERR: {err:?}");
            Err(NetworkError::Generic(err.to_string()))
        }

        None => {
            log::error!(target: "citadel", "P2P listener returned None. Stream dead");
            Err(NetworkError::InternalError("P2P Listener returned None"))
        }
    }
}

/// optionally returns a receiver that gets triggered once the connection is upgraded. Only returned when the stream is a client stream, not a server stream
#[cfg(not(target_family = "wasm"))]
#[allow(clippy::too_many_arguments)]
fn handle_p2p_stream<R: Ratchet, T: ProtocolIO>(
    mut p2p_stream: GenericNetworkStream,
    session_cid: DualRwLock<Option<u64>>,
    session: CitadelSession<R, T>,
    kernel_tx: UnboundedSender<NodeResult<R>>,
    from_listener: bool,
    v_conn: VirtualConnectionType,
    hole_punched_addr: TargettedSocketAddr,
    ticket: Ticket,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
) -> std::io::Result<()> {
    // SECURITY: Since this branch only occurs IF the primary session is connected, implying authentication has been performed
    let remote_peer = p2p_stream.peer_addr()?;
    let local_bind_addr = p2p_stream.local_addr()?;
    let quic_conn = p2p_stream
        .take_p2p_connection()
        .ok_or_else(|| generic_error("P2P Stream did not have QUIC connection loaded"))?;
    let udp_conn = QuicUdpSocketConnector::new(quic_conn, local_bind_addr);

    log::trace!(target: "citadel", "[P2P-stream {}] New stream from {:?}", from_listener.if_true("listener").if_false("client"), &remote_peer);
    let (sink, stream) = misc::safe_split_stream(p2p_stream);
    let (p2p_primary_stream_tx, p2p_primary_stream_rx) = unbounded();
    let p2p_primary_stream_tx = OutboundPrimaryStreamSender::from(p2p_primary_stream_tx);
    let p2p_primary_stream_rx = OutboundPrimaryStreamReceiver::from(p2p_primary_stream_rx);
    let header_obfuscator = HeaderObfuscator::new(
        from_listener,
        session_security_settings.header_obfuscator_settings,
    );
    let peer_cid = v_conn.get_target_cid();

    let (stopper_tx, stopper_rx) = channel();
    // Clone before passing to P2PInboundHandle since we need these for disconnect notification
    let session_cid_for_dc = session_cid.clone();
    // Get local CID for deterministic tie-breaker before session_cid is moved
    let implcid = session_cid.get().unwrap_or(0);
    let kernel_tx_for_dc = kernel_tx.clone();
    let p2p_handle = P2PInboundHandle::new(
        remote_peer,
        local_bind_addr.port(),
        session_cid,
        kernel_tx,
        p2p_primary_stream_tx.clone(),
        peer_cid,
    );
    let writer_future = CitadelSession::<R, T>::outbound_stream(
        p2p_primary_stream_rx,
        sink,
        header_obfuscator.clone(),
    );
    let reader_future = CitadelSession::execute_inbound_stream(
        stream,
        session.clone(),
        Some(p2p_handle),
        header_obfuscator,
    );
    let stopper_future = p2p_stopper(stopper_rx);

    let direct_p2p_remote = DirectP2PRemote::new(stopper_tx, p2p_primary_stream_tx, from_listener);
    let sess = session;

    // Create oneshot channel for P2P disconnect notification (bidirectional disconnect propagation)
    // Uses .take() pattern for exactly-once semantics - when VirtualConnection drops, it triggers the notifier
    let (p2p_dc_tx, p2p_dc_rx) = channel::<P2PDisconnectSignal>();

    let mut state_container = inner_mut_state!(sess.state_container);
    // if this is called from a client-side connection, forcibly upgrade since the client asserts its connection is what will be used

    // call upgrade, and, load udp socket
    state_container
        .insert_direct_p2p_connection(
            direct_p2p_remote,
            v_conn.get_target_cid(),
            implcid,
            Some(p2p_dc_tx),
        )
        .map_err(|err| generic_error(err.into_string()))?;

    // Capture the p2p_connection_id so the cleanup future can guard against
    // removing state that belongs to a newer connection for the same peer.
    let cleanup_connection_id = state_container
        .active_virtual_connections
        .get(&peer_cid)
        .map(|vconn| vconn.p2p_connection_id)
        .unwrap_or(Ticket(0));

    if udp_mode == UdpMode::Enabled {
        crate::proto::misc::udp_session_ops::spawn_udp_socket_loader(
            sess.clone(),
            v_conn,
            UdpSplittableTypes::Quic(udp_conn),
            hole_punched_addr,
            ticket,
            None,
        );
    }

    drop(state_container);

    // Clear P2P disconnect tracker for this peer so the new connection can
    // have its own disconnect signal. Done AFTER vconn insertion so that
    // token validation catches stale signals in the window after clearing.
    sess.session_manager
        .disconnect_tracker()
        .clear_p2p_peer(sess.kernel_ticket.get(), v_conn.get_target_cid());

    // Spawn task to handle P2P disconnect notification (bidirectional disconnect propagation)
    // When the vconn is dropped (stream ends or explicit disconnect), this task receives
    // the signal and:
    // 1. Sends PeerSignal::Disconnect via C2S to notify the remote peer
    // 2. Sends NodeResult::PeerEvent(Disconnect) to local kernel
    // One disconnect signal per peer session via tracker pattern.
    let sess_for_dc = sess.clone();
    let disconnect_tracker_for_dc = sess.session_manager.disconnect_tracker();
    let session_ticket_for_dc = sess.kernel_ticket.get();
    spawn!(async move {
        if let Ok(signal) = p2p_dc_rx.await {
            log::trace!(target: "citadel", "P2P disconnect notification received for peer {}: {:?}", signal.peer_cid, signal.reason);

            // Gate the entire handler behind the tracker to prevent both stale
            // C2S signals and duplicate kernel notifications. The tracker is
            // cleared by handle_p2p_connection when a new connection is established,
            // allowing the new connection instance to have its own disconnect signal.
            if !disconnect_tracker_for_dc.try_p2p_disconnect(session_ticket_for_dc, signal.peer_cid)
            {
                log::trace!(target: "citadel", "Skipping P2P D/C signal - already sent for session {:?} peer {}", session_ticket_for_dc, signal.peer_cid);
                return;
            }

            // Validate disconnect token: if a NEW P2P connection already exists for
            // this peer with a different connection_id, this signal is stale — skip it.
            if let Some(ref token) = signal.disconnect_token {
                let state_container = inner_state!(sess_for_dc.state_container);
                if let Some(current_vconn) = state_container
                    .active_virtual_connections
                    .get(&signal.peer_cid)
                {
                    if current_vconn.p2p_connection_id != token.connection_id {
                        log::trace!(target: "citadel", "Rejecting stale P2P disconnect signal for peer {} — new connection exists (expected {:?}, got {:?})", signal.peer_cid, current_vconn.p2p_connection_id, token.connection_id);
                        return;
                    }
                }
            }

            // 1. Send PeerSignal::Disconnect via C2S to notify remote peer
            if let Some(session_cid) = session_cid_for_dc.get() {
                let peer_signal = PeerSignal::Disconnect {
                    peer_conn_type: PeerConnectionType::LocalGroupPeer {
                        session_cid,
                        peer_cid: signal.peer_cid,
                    },
                    disconnect_response: Some(PeerResponse::Disconnected(format!(
                        "P2P disconnect: {:?}",
                        signal.reason
                    ))),
                    disconnect_token: signal.disconnect_token,
                };

                // Get C2S ratchet and send via primary stream
                if let Some(to_primary_stream) = sess_for_dc.to_primary_stream.as_ref() {
                    let state_container = inner_state!(sess_for_dc.state_container);
                    if let Ok(c2s_container) =
                        state_container.get_endpoint_container(C2S_IDENTITY_CID)
                    {
                        if let Some(ratchet) = c2s_container.ratchet_manager.get_ratchet(None) {
                            let timestamp = sess_for_dc.time_tracker.get_global_time_ns();
                            let security_level = state_container
                                .session_security_settings
                                .map(|s| s.security_level)
                                .unwrap_or(SecurityLevel::Standard);

                            let packet = packet_crafter::peer_cmd::craft_peer_signal(
                                &ratchet,
                                peer_signal,
                                signal.ticket.unwrap_or(Ticket(0)),
                                timestamp,
                                security_level,
                            );
                            if let Err(err) = to_primary_stream.unbounded_send(packet) {
                                log::warn!(target: "citadel", "Failed to send P2P disconnect signal via C2S: {err:?}");
                            } else {
                                log::trace!(target: "citadel", "Sent PeerSignal::Disconnect via C2S for peer {}", signal.peer_cid);
                            }
                        }
                    }
                }
            }

            // 2. Send NodeResult::PeerEvent(Disconnect) to local kernel
            let disconnect_result = NodeResult::PeerEvent(PeerEvent {
                event: PeerSignal::Disconnect {
                    peer_conn_type: PeerConnectionType::LocalGroupPeer {
                        session_cid: session_cid_for_dc.get().unwrap_or(0),
                        peer_cid: signal.peer_cid,
                    },
                    disconnect_response: Some(PeerResponse::Disconnected(format!(
                        "P2P disconnect: {:?}",
                        signal.reason
                    ))),
                    disconnect_token: signal.disconnect_token,
                },
                ticket: signal.ticket.unwrap_or(Ticket(0)),
                session_cid: session_cid_for_dc.get().unwrap_or(0),
            });
            let _ = kernel_tx_for_dc.unbounded_send(disconnect_result);
        }
    });

    let future = async move {
        let res = citadel_io::tokio::select! {
            res0 = writer_future => res0,
            res1 = reader_future => res1,
            res2 = stopper_future => res2
        };

        if let Err(err) = &res {
            // TODO: better error code handling
            if !err.to_string().contains("p2p stopper triggered") {
                log::error!(target: "citadel", "[P2P-stream] P2P stream ending. Reason: {err}");
            }
        }

        let mut state_container = inner_mut_state!(sess.state_container);

        // Only remove state if it still belongs to THIS P2P connection instance.
        // During reconnection, a newer connection may have already replaced this one
        // in the state container. Unconditional removal would delete the new
        // connection's state, causing "connection lost" errors.
        let is_current_connection = state_container
            .active_virtual_connections
            .get(&peer_cid)
            .map(|vconn| vconn.p2p_connection_id == cleanup_connection_id)
            .unwrap_or(false);

        if is_current_connection {
            state_container.remove_udp_channel(peer_cid);

            // Preserve the ratchet before removing the vconn so in-flight
            // packets (already in the processing pipeline) can still be
            // decrypted via stale_p2p_ratchets fallback in
            // get_orientation_safe_ratchet(). The stale ratchet is cleared
            // when a new connection for this peer is created.
            if let Some(ratchet) = state_container
                .active_virtual_connections
                .get(&peer_cid)
                .and_then(|vconn| vconn.get_endpoint_ratchet(None))
            {
                state_container.stale_p2p_ratchets.insert(peer_cid, ratchet);
            }

            state_container.active_virtual_connections.remove(&peer_cid);

            // NOTE: Do NOT remove peer_kem_states here — a new reconnection
            // may have already inserted fresh KEM state (same rationale as
            // commit b1325cf4 fix in peer_cmd_packet.rs and session_manager.rs).

            state_container
                .outgoing_peer_connect_attempts
                .remove(&peer_cid);
        } else {
            log::trace!(target: "citadel", "[P2P-stream] Skipping cleanup for peer {peer_cid} — connection replaced by newer instance");
        }

        log::trace!(target: "citadel", "[P2P-stream] Dropping tri-joined future");
        res
    };

    spawn!(future);

    Ok(())
}

pub struct P2PInboundHandle<R: Ratchet> {
    pub remote_peer: SocketAddr,
    pub local_bind_port: u16,
    // this has to be the CID of the local session, not the peer's CID
    pub session_cid: DualRwLock<Option<u64>>,
    pub kernel_tx: UnboundedSender<NodeResult<R>>,
    pub to_primary_stream: OutboundPrimaryStreamSender,
    pub peer_cid: u64,
}

impl<R: Ratchet> P2PInboundHandle<R> {
    fn new(
        remote_peer: SocketAddr,
        local_bind_port: u16,
        session_cid: DualRwLock<Option<u64>>,
        kernel_tx: UnboundedSender<NodeResult<R>>,
        to_primary_stream: OutboundPrimaryStreamSender,
        peer_cid: u64,
    ) -> Self {
        Self {
            remote_peer,
            local_bind_port,
            session_cid,
            kernel_tx,
            to_primary_stream,
            peer_cid,
        }
    }
}

async fn p2p_stopper(receiver: Receiver<()>) -> Result<(), NetworkError> {
    receiver
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    Err(NetworkError::InternalError("p2p stopper triggered"))
}

/// Both sides need to begin this process at `sync_time`
///
/// # Parameters
/// - `cancel_rx`: Optional cancellation signal. When the sender is dropped (e.g., on session
///   disconnect), the hole punch operation will be cancelled gracefully. This prevents orphaned
///   hole punch operations from interfering with reconnection attempts.
#[cfg(not(target_family = "wasm"))]
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(session_cid=session_cid.get(), peer_cid=peer_connection_type.get_original_target_cid()
    )
))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn attempt_simultaneous_hole_punch<R: Ratchet, T: ProtocolIO>(
    peer_connection_type: PeerConnectionType,
    ticket: Ticket,
    session: CitadelSession<R, T>,
    peer_nat_info: PeerNatInfo,
    session_cid: DualRwLock<Option<u64>>,
    kernel_tx: UnboundedSender<NodeResult<R>>,
    channel_signal: NodeResult<R>,
    sync_time: Instant,
    app: NetworkEndpoint,
    encrypted_config_container: HolePunchConfigContainer,
    client_config: T::ClientConfig,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
    cancel_rx: Option<Receiver<()>>,
    session_alive: SessionAliveTracker<R, T>,
) -> std::io::Result<()> {
    let client_config: Arc<rustls::ClientConfig> = T::client_config_to_any(&client_config)
        .and_then(|c| c.downcast::<Arc<rustls::ClientConfig>>().ok())
        .map(|c| *c)
        .ok_or_else(|| generic_error("P2P hole-punch requires native rustls client config"))?;
    let is_initiator = app.is_initiator();
    let kernel_tx = &kernel_tx;
    let v_conn = peer_connection_type.as_virtual_connection();

    let process = async move {
        if !session_alive.alive() {
            return Err(generic_error("Session no longer alive"));
        }
        citadel_io::time::sleep_until(sync_time).await;

        let hole_punched_socket = app
            .begin_udp_hole_punch(encrypted_config_container)
            .await
            .map_err(generic_error)?;
        let remote_connect_addr = hole_punched_socket.addr.send_address;
        let addr = hole_punched_socket.addr;
        let local_addr = hole_punched_socket.local_addr()?;
        log::trace!(target: "citadel", "~!@ P2P UDP Hole-punch finished @!~ | is initiator: {is_initiator}");

        // Sync point moved INTO the branches to ensure non-initiator's listener is ready
        // before initiator attempts to connect. This eliminates the 200ms race condition.
        if is_initiator {
            // Wait for non-initiator to create listener and signal ready
            app.sync().await.map_err(generic_error)?;
            log::trace!(target: "citadel", "Initiator: sync complete, non-initiator listener should be ready");

            let socket = hole_punched_socket.into_socket();
            let p2p_stream = crate::proto::misc::native_connect::p2p_connect_from_socket(
                socket,
                remote_connect_addr,
                peer_nat_info.tls_domain,
                client_config,
                None,
            )
            .await?;

            log::trace!(target: "citadel", "~!@ P2P UDP Hole-punch + QUIC finished successfully for INITIATOR @!~");
            handle_p2p_stream(
                p2p_stream,
                session_cid,
                session.clone(),
                kernel_tx.clone(),
                false,
                v_conn,
                addr,
                ticket,
                udp_mode,
                session_security_settings,
            )
        } else {
            log::trace!(target: "citadel", "Non-initiator: creating listener before signaling ready");

            // Reuse the hole-punched socket directly for QUIC listener.
            // This eliminates the drop-and-rebind race where the OS may not
            // release the port in time for a new socket to bind.
            let socket = hole_punched_socket.into_socket();

            // Create listener BEFORE sync to ensure it's ready when initiator connects
            let (listener, _) = crate::proto::misc::native_connect::p2p_listener_from_socket(
                socket, None, local_addr,
            )?;
            log::trace!(target: "citadel", "Non-initiator: listener created (socket reused) on {:?}, signaling ready", local_addr);

            // Signal to initiator that listener is ready
            app.sync().await.map_err(generic_error)?;

            // Now accept the connection
            p2p_conn_handler(
                listener,
                session.clone(),
                remote_connect_addr,
                v_conn,
                addr,
                ticket,
                udp_mode,
                session_security_settings,
            )
            .await
            .map_err(|err| generic_error(format!("Non-initiator was unable to secure connection despite hole-punching success: {err:?}")))
        }
    };

    // Add timeout to prevent indefinite hang during P2P connection establishment.
    // If the initiator fails to connect or the non-initiator's listener never receives
    // a connection, we need to timeout rather than hang forever.
    const P2P_CONN_TIMEOUT: Duration = Duration::from_secs(30);

    // Wrap the process with timeout and optional cancellation signal.
    // The cancellation signal allows graceful shutdown when the session disconnects,
    // preventing orphaned hole punch operations from interfering with reconnection attempts.
    let timed_process = citadel_io::time::timeout(P2P_CONN_TIMEOUT, process);

    let result = if let Some(mut cancel_rx) = cancel_rx {
        citadel_io::tokio::select! {
            res = timed_process => res,
            _ = &mut cancel_rx => {
                log::info!(target: "citadel", "[Hole-punch/Cancelled] Hole punch cancelled by session shutdown");
                return Ok(()); // Early return - cancelled, skip sending channel signal
            }
        }
    } else {
        timed_process.await
    };

    match result {
        Ok(Ok(())) => {
            log::trace!(target: "citadel", "[Hole-punch] P2P connection established successfully");
        }
        Ok(Err(err)) => {
            log::warn!(target: "citadel", "[Hole-punch/Err] {err:?}");
        }
        Err(_elapsed) => {
            log::warn!(target: "citadel", "[Hole-punch/Timeout] P2P connection establishment timed out after {}s", P2P_CONN_TIMEOUT.as_secs());
        }
    }

    log::trace!(target: "citadel", "Sending channel to kernel");
    // TODO: Early send IF NAT traversal determined not to be possible, or ...
    // early send anyways, and, upgrade the p2p channel in the state container automatically
    kernel_tx
        .unbounded_send(channel_signal)
        .map_err(|_| generic_error("Unable to send signal to kernel"))?;

    Ok(())
}

pub(crate) fn generic_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    err: E,
) -> std::io::Error {
    std::io::Error::other(err)
}
