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
use crate::prelude::ServerUnderlyingProtocol;
use crate::proto::misc;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::proto::misc::udp_internal_interface::{QuicUdpSocketConnector, UdpSplittableTypes};
use crate::proto::node::CitadelNode;
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
use crate::proto::session::CitadelSession;
use crate::proto::state_container::{P2PDisconnectSignal, VirtualConnectionType};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_types::prelude::{SessionSecuritySettings, UdpMode};
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
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

#[allow(clippy::too_many_arguments)]
async fn p2p_conn_handler<R: Ratchet>(
    mut p2p_listener: GenericNetworkListener,
    session: CitadelSession<R>,
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
#[allow(clippy::too_many_arguments)]
fn handle_p2p_stream<R: Ratchet>(
    mut p2p_stream: GenericNetworkStream,
    session_cid: DualRwLock<Option<u64>>,
    session: CitadelSession<R>,
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
        .take_quic_connection()
        .ok_or_else(|| generic_error("P2P Stream did not have QUIC connection loaded"))?;
    let udp_conn = QuicUdpSocketConnector::new(quic_conn, local_bind_addr);

    log::trace!(target: "citadel", "[P2P-stream {}] New stream from {:?}", from_listener.if_true("listener").if_false("client"), &remote_peer);
    let (sink, stream) = misc::net::safe_split_stream(p2p_stream);
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
    let kernel_tx_for_dc = kernel_tx.clone();
    let p2p_handle = P2PInboundHandle::new(
        remote_peer,
        local_bind_addr.port(),
        session_cid,
        kernel_tx,
        p2p_primary_stream_tx.clone(),
        peer_cid,
    );
    let writer_future = CitadelSession::<R>::outbound_stream(
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
        .insert_direct_p2p_connection(direct_p2p_remote, v_conn.get_target_cid(), Some(p2p_dc_tx))
        .map_err(|err| generic_error(err.into_string()))?;

    if udp_mode == UdpMode::Enabled {
        CitadelSession::udp_socket_loader(
            sess.clone(),
            v_conn,
            UdpSplittableTypes::Quic(udp_conn),
            hole_punched_addr,
            ticket,
            None,
        );
    }

    drop(state_container);

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
            // NOTE: NodeResult::Disconnect is for C2S only; P2P uses PeerEvent
            // Check tracker to ensure at most 1 P2P disconnect signal per session/peer
            if !disconnect_tracker_for_dc.try_p2p_disconnect(session_ticket_for_dc, signal.peer_cid)
            {
                log::trace!(target: "citadel", "Skipping P2P D/C signal - already sent for session {:?} peer {}", session_ticket_for_dc, signal.peer_cid);
                return;
            }

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
        state_container.active_virtual_connections.remove(&peer_cid);
        state_container
            .outgoing_peer_connect_attempts
            .remove(&peer_cid);

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
pub(crate) async fn attempt_simultaneous_hole_punch<R: Ratchet>(
    peer_connection_type: PeerConnectionType,
    ticket: Ticket,
    session: CitadelSession<R>,
    peer_nat_info: PeerNatInfo,
    session_cid: DualRwLock<Option<u64>>,
    kernel_tx: UnboundedSender<NodeResult<R>>,
    channel_signal: NodeResult<R>,
    sync_time: Instant,
    app: NetworkEndpoint,
    encrypted_config_container: HolePunchConfigContainer,
    client_config: Arc<rustls::ClientConfig>,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
    cancel_rx: Option<Receiver<()>>,
) -> std::io::Result<()> {
    let is_initiator = app.is_initiator();
    let kernel_tx = &kernel_tx;
    let v_conn = peer_connection_type.as_virtual_connection();

    let process = async move {
        citadel_io::tokio::time::sleep_until(sync_time).await;

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
            let quic_endpoint = citadel_wire::quic::QuicClient::new_with_rustls_config(
                socket,
                client_config.clone(),
            )
            .map_err(generic_error)?;
            let p2p_stream = CitadelNode::<R>::quic_p2p_connect_defaults(
                quic_endpoint.endpoint,
                None,
                peer_nat_info.tls_domain,
                remote_connect_addr,
                client_config,
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
            drop(hole_punched_socket); // drop to prevent conflicts caused by SO_REUSE_ADDR

            // Create listener BEFORE sync to ensure it's ready when initiator connects
            let (listener, _) = CitadelNode::<R>::create_listen_socket(
                ServerUnderlyingProtocol::new_quic_self_signed(),
                None,
                None,
                local_addr,
            )?;
            log::trace!(target: "citadel", "Non-initiator: listener created on {:?}, signaling ready", local_addr);

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
    let timed_process = citadel_io::tokio::time::timeout(P2P_CONN_TIMEOUT, process);

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
