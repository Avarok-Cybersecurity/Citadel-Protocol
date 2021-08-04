use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio_stream::StreamExt;

use hyxe_crypt::drill::SecurityLevel;

use crate::error::NetworkError;
use crate::functional::IfTrueConditional;
use crate::hdp::hdp_packet_processor::includes::{Duration, hdp_packet_crafter, Instant, SocketAddr};
use crate::hdp::hdp_server::{HdpServer, HdpServerResult, Ticket};
use crate::hdp::hdp_session::{HdpSession, SessionState};
use crate::hdp::misc;
use crate::hdp::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::hdp::outbound_sender::{OutboundPrimaryStreamReceiver, unbounded, UnboundedSender};
use crate::hdp::outbound_sender::OutboundPrimaryStreamSender;
use crate::hdp::peer::peer_crypt::{KeyExchangeProcess, PeerNatInfo};
use crate::hdp::peer::peer_layer::{PeerConnectionType, PeerSignal};
use crate::hdp::misc::dual_cell::DualCell;
use crate::hdp::state_container::StateContainer;
use crate::hdp::misc::panic_future::AssertSendSafeFuture;
use hyxe_nat::udp_traversal::synchronization_phase::UdpHolePuncher;
use hyxe_nat::exports::Endpoint;

pub struct DirectP2PRemote {
    // immediately causes connection to end
    stopper: Option<Sender<()>>,
    pub p2p_primary_stream: OutboundPrimaryStreamSender,
    pub from_listener: bool,
    pub fallback: Option<u64>
}

impl DirectP2PRemote {
    fn new(stopper: Sender<()>, p2p_primary_stream: OutboundPrimaryStreamSender, from_listener: bool) -> Self {
        Self { stopper: Some(stopper), p2p_primary_stream, from_listener, fallback: None }
    }
}

impl Drop for DirectP2PRemote {
    fn drop(&mut self) {
        log::info!("[DirectP2PRemote] dropping p2p connection (type: {})...", self.from_listener.if_true("listener").if_false("client"));
        if let Some(stopper) = self.stopper.take() {
            if let Err(_) = stopper.send(()) {
                //log::error!("Unable to alert p2p-stopper")
            }
        }
    }
}

pub async fn p2p_conn_handler(mut p2p_listener: GenericNetworkListener, session: HdpSession) -> Result<(), NetworkError> {
    let kernel_tx = session.kernel_tx.clone();
    let implicated_cid = session.implicated_cid.clone();
    let ref weak = session.as_weak();

    std::mem::drop(session);

    log::info!("[P2P-stream] Beginning async p2p listener subroutine on {:?}", p2p_listener.local_addr().unwrap());

    loop {
        match p2p_listener.next().await {
            Some(Ok((p2p_stream, _))) => {
                let session = HdpSession::upgrade_weak(weak).ok_or(NetworkError::InternalError("HdpSession dropped"))?;
                if session.state.get() != SessionState::Connected {
                    log::warn!("Blocked an eager p2p connection (session state not yet connected)");
                    continue;
                }

                if let Err(err) = handle_p2p_stream(p2p_stream,implicated_cid.clone(), session.clone(), kernel_tx.clone(), true) {
                    log::error!("[P2P-stream] Unable to handle P2P stream: {:?}", err);
                }
            }

            Some(Err(err)) => {
                // on android/ios, when the program is backgrounded for days then turned on, this error will loop endlessly. As such, drop this future and end the session to give the program the chance to create a session anew
                //const ERR_INVALID_ARGUMENT: i32 = 22;
                log::error!("[P2P-stream] ERR: {:?}", err);
                return Err(NetworkError::Generic(err.to_string()))
            }

            None => {
                log::error!("P2P listener returned None. Stream dead");
                return Err(NetworkError::InternalError("P2P Listener returned None"))
            }
        }
    }
}

fn handle_p2p_stream(p2p_stream: GenericNetworkStream, implicated_cid: DualCell<Option<u64>>, session: HdpSession, kernel_tx: UnboundedSender<HdpServerResult>, from_listener: bool) -> std::io::Result<OutboundPrimaryStreamSender> {
    // SECURITY: Since this branch only occurs IF the primary session is connected, then the primary user is
    // logged-in. However, what if a malicious user decides to connect here?
    // They won't be able to register through here, since registration requires that the state is NeedsRegister
    // or SocketJustOpened. But, what if the primary sessions just started and a user tries registering through
    // here? Well, just as explained, this branch requires a login in order to occur. Thus, it's impossible for
    // a rogue user to attempt to register through here. All other packet types, even pre-connect, require
    // p2p endpoint crypto, so a rogue connector wouldn't be able to do anything without compromising the crypto
    let remote_peer = p2p_stream.peer_addr()?;
    let local_bind_addr = p2p_stream.local_addr()?;
    log::info!("[P2P-stream {}] New stream from {:?}", from_listener.if_true("listener").if_false("client"), &remote_peer);
    let (sink, stream) = misc::net::safe_split_stream(p2p_stream);
    let (p2p_primary_stream_tx, p2p_primary_stream_rx) = unbounded();
    let p2p_primary_stream_tx = OutboundPrimaryStreamSender::from(p2p_primary_stream_tx);
    let p2p_primary_stream_rx = OutboundPrimaryStreamReceiver::from(p2p_primary_stream_rx);
    //let (header_obfuscator, packet_opt) = HeaderObfuscator::new(from_listener);

    let (stopper_tx, stopper_rx) = channel();
    let p2p_handle = P2PInboundHandle::new(remote_peer, local_bind_addr.port(), implicated_cid.clone(), kernel_tx.clone(), p2p_primary_stream_tx.clone());
    let writer_future = HdpSession::outbound_stream(p2p_primary_stream_rx, sink);
    let reader_future = HdpSession::execute_inbound_stream(stream, session.clone(), Some(p2p_handle));
    let stopper_future = p2p_stopper(stopper_rx);

    let direct_p2p_remote = DirectP2PRemote::new(stopper_tx, p2p_primary_stream_tx.clone(), from_listener);
    let sess = session;
    let mut state_container = inner_mut!(sess.state_container);
    if !state_container.load_provisional_direct_p2p_remote(remote_peer, direct_p2p_remote) {
        log::warn!("[P2P-stream] Peer from {:?} already trying to connect. Dropping connection", remote_peer);
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "dropping concurrent connection"))
    } else {
        log::info!("Successfully loaded conn for addr: {:?}", remote_peer);
    }

    std::mem::drop(state_container);

    // have the conn automatically drop after 5s if it's still a provisional type
    sess.queue_worker.insert_oneshot(Duration::from_millis(3000), move |state_container| {
        if let Some(conn) = state_container.provisional_direct_p2p_conns.remove(&remote_peer) {
            if let Some(peer_cid) = conn.fallback.clone() {
                // since this connection was marked as a fallback, we need to upgrade it
                log::info!("[Fallback] will see if we need to upgrade the connection to {:?}", remote_peer);
                if let Some(vconn) = state_container.active_virtual_connections.get_mut(&peer_cid) {
                    if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                        if endpoint_container.direct_p2p_remote.is_none() {
                            log::info!("[Fallback] Upgrading connection {}@{:?}", peer_cid, remote_peer);
                            endpoint_container.direct_p2p_remote = Some(conn);
                        } else {
                            log::info!("[Fallback] no need to upgrade stream")
                        }
                    }
                } else {
                    log::warn!("Unable to find vconn for cid {}", peer_cid);
                }
            } else {
                log::warn!("Removed stale *{}* P2P connection to {:?}", conn.from_listener.if_true("listener").if_false("client"), remote_peer);
            }
        }
    });

    let future = async move {
        let res = tokio::select! {
            res0 = writer_future => res0,
            res1 = reader_future => res1,
            res2 = stopper_future => res2
        };

        if let Err(err) = res {
            log::info!("[P2P-stream] P2P stream ending. Reason: {}", err.to_string());
        }

        log::info!("[P2P-stream] Dropping tri-joined future");
        Ok(())
    };

    sess.p2p_session_tx.as_ref().unwrap().unbounded_send(Box::pin(AssertSendSafeFuture::new(future))).map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))?;

    //let _ = spawn!(future);

    // send the packet, if necessary
    /*
    if let Some(zero) = packet_opt {
        p2p_primary_stream_tx.unbounded_send(zero).map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))?;
    }*/

    Ok(p2p_primary_stream_tx)
}


pub struct P2PInboundHandle {
    pub remote_peer: SocketAddr,
    pub local_bind_port: u16,
    // this has to be the CID of the local session, not the peer's CID
    pub implicated_cid: DualCell<Option<u64>>,
    pub kernel_tx: UnboundedSender<HdpServerResult>,
    pub to_primary_stream: OutboundPrimaryStreamSender
}

impl P2PInboundHandle {
    fn new(remote_peer: SocketAddr, local_bind_port: u16, implicated_cid: DualCell<Option<u64>>, kernel_tx: UnboundedSender<HdpServerResult>, to_primary_stream: OutboundPrimaryStreamSender) -> Self {
        Self { remote_peer, local_bind_port, implicated_cid, kernel_tx, to_primary_stream }
    }
}

async fn p2p_stopper(receiver: Receiver<()>) -> Result<(), NetworkError> {
    receiver.await.map_err(|err| NetworkError::Generic(err.to_string()))?;
    Err(NetworkError::InternalError("p2p stopper triggered"))
}

/// Both sides need to begin this process at `sync_time` to bypass the firewall
#[allow(warnings)]
pub async fn attempt_simultaneous_hole_punch(peer_connection_type: PeerConnectionType, ticket: Ticket, ref session: HdpSession, peer_nat_info: PeerNatInfo, implicated_cid: DualCell<Option<u64>>, kernel_tx: UnboundedSender<HdpServerResult>, channel_signal: HdpServerResult, sync_time: Instant,
                                             ref state_container: StateContainer, security_level: SecurityLevel, hole_puncher: UdpHolePuncher<'static>, quic_endpoint: Endpoint) -> std::io::Result<()> {

    tokio::time::sleep_until(sync_time).await;

    let task = async move {
        let hole_punched_socket = hole_puncher.await.map_err(|err| generic_error(err))?;
        let remote_connect_addr = hole_punched_socket.addr.natted;
        std::mem::drop(hole_punched_socket);
        log::info!("~!@ P2P UDP Hole-punch finished @!~");
        HdpServer::create_p2p_quic_connect_socket(quic_endpoint, remote_connect_addr, peer_nat_info.tls_domain, None).await
    };

    // now, wait for the first successfull future
    let res = tokio::time::timeout(Duration::from_millis(3000), task).await.map_err(|err| generic_error("Deadline for TCP hole puncher elapsed"))?;
    log::info!("~!@ P2P UDP Hole-punch + QUIC finished. Res: {} @!~", res.is_ok());
    let expected_peer_cid = peer_connection_type.get_original_target_cid();
    let res = match res {
        Ok(p2p_stream) => {
            log::info!("[P2P-stream] SUCCESS TCP Hole Punching. Setting up direct p2p session ...");
            let peer_endpoint_addr = p2p_stream.peer_addr()?;

            handle_p2p_stream(p2p_stream, implicated_cid, session.clone(), kernel_tx.clone(), false)
                .and_then(move |p2p_outbound_stream| {
                    // This node obtained a stream. However, this doesn't mean we get to keep it.
                    // if the other node didn't get its own connection, then this node keeps its connection.
                    // if the other node did get its own connection, then that means both this node and the other
                    // node managed to traverse the NAT. Since we only want one TCP connection, we need to determine
                    // which node keeps its connection. In that case, the side that is the "initiator" gets to keep
                    // its connection
                    log::warn!("[P2P-stream/client] Success connecting to {:?}", peer_endpoint_addr);
                    let success_signal = PeerSignal::Kem(peer_connection_type, KeyExchangeProcess::HolePunchEstablished);
                    send_hole_punch_packet(session, success_signal, state_container, ticket, expected_peer_cid, Some(&p2p_outbound_stream), security_level)
                })
        }

        Err(err) => {
            // Since this node gets no stream, it doesn't matter if we're the initiator or not. We discard the connection,
            // and alert the other side so that it may keep its connection (if established)
            log::warn!("Hole-punching using this TCP stream failed. Reason: {:?}. Sending failure packet", err);
            let fail_signal = PeerSignal::Kem(peer_connection_type, KeyExchangeProcess::HolePunchFailed);
            send_hole_punch_packet(session, fail_signal, state_container, ticket, expected_peer_cid, None, security_level)
                .and_then(|_| Err(std::io::Error::new(std::io::ErrorKind::Other, "Could not TCP hole-punch")))
        }
    };

    // If STUN succeeded, then the channel will use the latest conn. Else, it will use TURN-like routing by default
    // To prevent the weird bug that ocurred in release mode relating to missing packets, we return that channel only after we conclude hole-punching
    kernel_tx.unbounded_send(channel_signal).map_err(|_| generic_error("Unable to send signal to kernel"))?;
    res
}

fn send_hole_punch_packet(session: &HdpSession, signal: PeerSignal, state_container: &StateContainer, ticket: Ticket, expected_peer_cid: u64, p2p_outbound_stream_opt: Option<&OutboundPrimaryStreamSender>, security_level: SecurityLevel) -> std::io::Result<()> {
    let endpoint_hyper_ratchet = inner!(state_container).active_virtual_connections.get(&expected_peer_cid).ok_or_else(|| generic_error("Active Vconn not loaded"))?.endpoint_container.as_ref().ok_or_else(|| generic_error("Endpoint container not loaded"))?.endpoint_crypto.get_hyper_ratchet(None).ok_or_else(|| generic_error("Peer hyper ratchet does not exist"))?.clone();
    let sess = session;
    let p2p_outbound_stream = p2p_outbound_stream_opt.unwrap_or_else(|| sess.to_primary_stream.as_ref().unwrap());
    let timestamp = sess.time_tracker.get_global_time_ns();
    let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal_endpoint(&endpoint_hyper_ratchet, signal, ticket, timestamp, expected_peer_cid, security_level);
    log::info!("***ABT TO SEND {} PACKET***", p2p_outbound_stream_opt.is_some().if_true("SUCCESS").if_false("FAILURE"));
    p2p_outbound_stream.unbounded_send(packet)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
}

pub(crate) fn generic_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}