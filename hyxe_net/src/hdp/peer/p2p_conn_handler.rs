use crate::hdp::hdp_packet_processor::includes::{SocketAddr, Instant, hdp_packet_crafter, Duration};
use tokio::net::{TcpListener, TcpStream};
use crate::hdp::hdp_session::{HdpSession, SessionState};
use crate::error::NetworkError;
use tokio::stream::StreamExt;
use crate::hdp::misc;
use crate::hdp::outbound_sender::{unbounded, UnboundedSender};
use std::sync::Arc;
use atomic::Atomic;
use crate::hdp::hdp_server::{HdpServerResult, HdpServer, Ticket};
use tokio::sync::oneshot::{Receiver, Sender, channel};
use crate::hdp::peer::peer_layer::{PeerSignal, PeerConnectionType};
use crate::hdp::peer::peer_crypt::KeyExchangeProcess;
use crate::hdp::outbound_sender::OutboundTcpSender;
use crate::hdp::hdp_packet::HeaderObfuscator;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::drill::SecurityLevel;
use crate::functional::IfTrueConditional;

pub struct DirectP2PRemote {
    // immediately causes connection to end
    stopper: Option<Sender<()>>,
    pub p2p_primary_stream: OutboundTcpSender,
    pub from_listener: bool,
    pub fallback: Option<u64>
}

impl DirectP2PRemote {
    fn new(stopper: Sender<()>, p2p_primary_stream: OutboundTcpSender, from_listener: bool) -> Self {
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

#[allow(unreachable_code, warnings)]
pub async fn p2p_conn_handler(mut p2p_listener: TcpListener, session: HdpSession) -> Result<(), NetworkError> {
    let (ref kernel_tx, ref implicated_cid, ref weak) = {
        let sess = inner!(session);
        let kernel_tx = sess.kernel_tx.clone();
        let implicated_cid = sess.implicated_cid.clone();
        std::mem::drop(sess);
        let weak = session.as_weak();
        std::mem::drop(session);
        (kernel_tx, implicated_cid, weak)
    };

    log::info!("[P2P-stream] Beginning async p2p listener subroutine on {:?}", p2p_listener.local_addr().unwrap());
    while let Some(p2p_stream) = p2p_listener.next().await {
        let session = HdpSession::upgrade_weak(weak).ok_or(NetworkError::InternalError("Unable to upgrade Weak"))?;
        let sess = inner!(session);
        if sess.state != SessionState::Connected {
            log::warn!("Blocked an eager p2p connection (session state not yet connected)");
            continue;
        }

        match p2p_stream {
            Ok(p2p_stream) => {
                if let Err(err) = handle_p2p_stream(p2p_stream, implicated_cid.clone(), session.clone(), kernel_tx.clone(), true) {
                    log::error!("[P2P-stream] Unable to handle P2P stream: {:?}", err);
                }
            },

            Err(err) =>{
                log::error!("[P2P-stream] ERR: {:?}", err);
            }
        }
    }
    Err(NetworkError::InternalError("Ended"))
}

fn handle_p2p_stream(p2p_stream: TcpStream, implicated_cid: Arc<Atomic<Option<u64>>>, session: HdpSession, kernel_tx: UnboundedSender<HdpServerResult>, from_listener: bool) -> std::io::Result<OutboundTcpSender> {
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
    let p2p_primary_stream_tx = OutboundTcpSender::from(p2p_primary_stream_tx);
    let (header_obfuscator, packet_opt) = HeaderObfuscator::new(from_listener);

    let (stopper_tx, stopper_rx) = channel();
    let p2p_handle = P2PInboundHandle::new(remote_peer, local_bind_addr.port(), implicated_cid.clone(), kernel_tx.clone(), p2p_primary_stream_tx.clone());
    let writer_future = HdpSession::outbound_stream(p2p_primary_stream_rx, sink, header_obfuscator.clone());
    let reader_future = HdpSession::execute_inbound_stream(stream, session.clone(), Some(p2p_handle), header_obfuscator);
    let stopper_future = p2p_stopper(stopper_rx);

    let direct_p2p_remote = DirectP2PRemote::new(stopper_tx, p2p_primary_stream_tx.clone(), from_listener);
    let sess = inner!(session);
    let mut state_container = inner_mut!(sess.state_container);
    if !state_container.load_provisional_direct_p2p_remote(remote_peer, direct_p2p_remote) {
        log::warn!("[P2P-stream] Peer from {:?} already trying to connect. Dropping connection", remote_peer);
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "dropping concurrent connection"))
    } else {
        log::info!("Successfully loaded conn for addr: {:?}", remote_peer);
    }

    // have the conn automatically drop after 5s if it's still a provisional type
    sess.queue_worker.insert_oneshot(Duration::from_millis(3000), move |sess| {
        let mut state_container = inner_mut!(sess.state_container);
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
        if let Err(err) = futures::future::try_join3(writer_future, reader_future, stopper_future).await {
            log::info!("[P2P-stream] P2P stream ending. Reason: {}", err.to_string());
        }

        log::info!("[P2P-stream] Dropping tri-joined future");
    };

    let _ = spawn!(future);

    // send the packet, if necessary
    if let Some(zero) = packet_opt {
        p2p_primary_stream_tx.unbounded_send(zero).map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))?;
    }

    Ok(p2p_primary_stream_tx)
}


pub struct P2PInboundHandle {
    pub remote_peer: SocketAddr,
    pub local_bind_port: u16,
    // this has to be the CID of the local session, not the peer's CID
    pub implicated_cid: Arc<Atomic<Option<u64>>>,
    pub kernel_tx: UnboundedSender<HdpServerResult>,
    pub to_primary_stream: OutboundTcpSender
}

impl P2PInboundHandle {
    fn new(remote_peer: SocketAddr, local_bind_port: u16, implicated_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, to_primary_stream: OutboundTcpSender) -> Self {
        Self { remote_peer, local_bind_port, implicated_cid, kernel_tx, to_primary_stream }
    }
}

async fn p2p_stopper(receiver: Receiver<()>) -> Result<(), NetworkError> {
    receiver.await.map_err(|err| NetworkError::Generic(err.to_string()))?;
    Err(NetworkError::InternalError("p2p stopper triggered"))
}

/// Both sides need to begin this process at `sync_time` to bypass the firewall
#[allow(warnings)]
pub async fn attempt_tcp_simultaneous_hole_punch(peer_connection_type: PeerConnectionType, ticket: Ticket, session: HdpSession, peer_endpoint_addr: SocketAddr, implicated_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, sync_time: Instant,
endpoint_hyper_ratchet: HyperRatchet, security_level: SecurityLevel) -> std::io::Result<()> {

    tokio::time::delay_until(sync_time).await;
    let expected_peer_cid = peer_connection_type.get_original_target_cid();
    log::info!("[P2P-stream] Attempting to hole-punch to {:?} ({})", &peer_endpoint_addr, expected_peer_cid);
    if let Ok(p2p_stream) = HdpServer::create_reuse_tcp_connect_socket(peer_endpoint_addr, None).await {
        log::info!("[P2P-stream] SUCCESS TCP Hole Punching. Setting up direct p2p session ...");
        handle_p2p_stream(p2p_stream, implicated_cid, session.clone(), kernel_tx, false)
            .and_then(move |p2p_outbound_stream| {
                // This node obtained a stream. However, this doesn't mean we get to keep it.
                // if the other node didn't get its own connection, then this node keeps its connection.
                // if the other node did get its own connection, then that means both this node and the other
                // node managed to traverse the NAT. Since we only want one TCP connection, we need to determine
                // which node keeps its connection. In that case, the side that is the "initiator" gets to keep
                // its connection
                log::warn!("[P2P-stream/client] Success connecting to {:?}", peer_endpoint_addr);
                let success_signal = PeerSignal::Kem(peer_connection_type, KeyExchangeProcess::HolePunchEstablished);
                send_hole_punch_packet(session, success_signal, endpoint_hyper_ratchet, ticket, expected_peer_cid, Some(&p2p_outbound_stream), security_level)
            })
    } else {
        // Since this node gets no stream, it doesn't matter if we're the initiator or not. We discard the connection,
        // and alert the other side so that it may keep its connection (if established)
        log::warn!("Unable to connect to {:?}. Sending failure packet", peer_endpoint_addr);
        let fail_signal = PeerSignal::Kem(peer_connection_type, KeyExchangeProcess::HolePunchFailed);
        send_hole_punch_packet(session, fail_signal, endpoint_hyper_ratchet, ticket, expected_peer_cid, None, security_level)
    }
}

fn send_hole_punch_packet(session: HdpSession, signal: PeerSignal, endpoint_hyper_ratchet: HyperRatchet, ticket: Ticket, expected_peer_cid: u64, p2p_outbound_stream_opt: Option<&OutboundTcpSender>, security_level: SecurityLevel) -> std::io::Result<()> {
    let sess = inner!(session);
    let p2p_outbound_stream = p2p_outbound_stream_opt.unwrap_or_else(|| sess.to_primary_stream.as_ref().unwrap());
    let timestamp = sess.time_tracker.get_global_time_ns();
    let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal_endpoint(&endpoint_hyper_ratchet, signal, ticket, timestamp, expected_peer_cid, security_level);
    log::info!("***ABT TO SEND {} PACKET***", p2p_outbound_stream_opt.is_some().if_true("SUCCESS").if_false("FAILURE"));
    p2p_outbound_stream.unbounded_send(packet)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
}