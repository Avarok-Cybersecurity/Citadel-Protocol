use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio_stream::StreamExt;

use crate::error::NetworkError;
use crate::functional::IfTrueConditional;
use crate::prelude::ServerUnderlyingProtocol;
use crate::proto::misc;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::proto::misc::udp_internal_interface::{QuicUdpSocketConnector, UdpSplittableTypes};
use crate::proto::node::Node;
use crate::proto::node_result::NodeResult;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::outbound_sender::{unbounded, OutboundPrimaryStreamReceiver, UnboundedSender};
use crate::proto::packet_processor::includes::{Duration, Instant, SocketAddr};
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::HdpSession;
use crate::proto::state_container::VirtualConnectionType;
use citadel_user::re_exports::__private::Formatter;
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use citadel_wire::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use std::fmt::Debug;
use std::sync::Arc;

pub struct DirectP2PRemote {
    // immediately causes connection to end
    stopper: Option<Sender<()>>,
    pub p2p_primary_stream: OutboundPrimaryStreamSender,
    pub from_listener: bool,
}

impl Debug for DirectP2PRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> citadel_user::re_exports::__private::fmt::Result {
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

async fn setup_listener_non_initiator(
    local_bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    session: HdpSession,
    v_conn: VirtualConnectionType,
    hole_punched_addr: TargettedSocketAddr,
    ticket: Ticket,
) -> Result<(), NetworkError> {
    // TODO: use custom self-signed
    let (listener, _) = Node::create_listen_socket(
        ServerUnderlyingProtocol::new_quic_self_signed(),
        None,
        None,
        local_bind_addr,
    )?;
    p2p_conn_handler(
        listener,
        session,
        remote_addr,
        v_conn,
        hole_punched_addr,
        ticket,
    )
    .await
}

async fn p2p_conn_handler(
    mut p2p_listener: GenericNetworkListener,
    session: HdpSession,
    _necessary_remote_addr: SocketAddr,
    v_conn: VirtualConnectionType,
    hole_punched_addr: TargettedSocketAddr,
    ticket: Ticket,
) -> Result<(), NetworkError> {
    let kernel_tx = session.kernel_tx.clone();
    let implicated_cid = session.implicated_cid.clone();
    let weak = &session.as_weak();

    std::mem::drop(session);

    log::trace!(target: "citadel", "[P2P-stream] Beginning async p2p listener subroutine on {:?}", p2p_listener.local_addr().unwrap());

    match p2p_listener.next().await {
        Some(Ok((p2p_stream, _))) => {
            let session = HdpSession::upgrade_weak(weak)
                .ok_or(NetworkError::InternalError("HdpSession dropped"))?;

            /*
            if p2p_stream.peer_addr()?.ip() != necessary_remote_addr.ip() {
                log::warn!(target: "citadel", "Blocked p2p connection from {:?} since IP does not match {:?}", p2p_stream, necessary_remote_addr);
                continue;
            }*/

            handle_p2p_stream(
                p2p_stream,
                implicated_cid,
                session,
                kernel_tx,
                true,
                v_conn,
                hole_punched_addr,
                ticket,
            )?;
            Ok(())
        }

        Some(Err(err)) => {
            // on android/ios, when the program is backgrounded for days then turned on, this error will loop endlessly. As such, drop this future and end the session to give the program the chance to create a session anew
            //const ERR_INVALID_ARGUMENT: i32 = 22;
            log::error!(target: "citadel", "[P2P-stream] ERR: {:?}", err);
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
fn handle_p2p_stream(
    mut p2p_stream: GenericNetworkStream,
    implicated_cid: DualRwLock<Option<u64>>,
    session: HdpSession,
    kernel_tx: UnboundedSender<NodeResult>,
    from_listener: bool,
    v_conn: VirtualConnectionType,
    hole_punched_addr: TargettedSocketAddr,
    ticket: Ticket,
) -> std::io::Result<()> {
    // SECURITY: Since this branch only occurs IF the primary session is connected, then the primary user is
    // logged-in. However, what if a malicious user decides to connect here?
    // They won't be able to register through here, since registration requires that the state is NeedsRegister
    // or SocketJustOpened. But, what if the primary sessions just started and a user tries registering through
    // here? Well, just as explained, this branch requires a login in order to occur. Thus, it's impossible for
    // a rogue user to attempt to register through here. All other packet types, even pre-connect and NAT traversal, require
    // p2p endpoint crypto, so a rogue connector wouldn't be able to do anything
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
    //let (header_obfuscator, packet_opt) = HeaderObfuscator::new(from_listener);

    let (stopper_tx, stopper_rx) = channel();
    let p2p_handle = P2PInboundHandle::new(
        remote_peer,
        local_bind_addr.port(),
        implicated_cid,
        kernel_tx,
        p2p_primary_stream_tx.clone(),
    );
    let writer_future = HdpSession::outbound_stream(p2p_primary_stream_rx, sink);
    let reader_future =
        HdpSession::execute_inbound_stream(stream, session.clone(), Some(p2p_handle));
    let stopper_future = p2p_stopper(stopper_rx);

    let direct_p2p_remote = DirectP2PRemote::new(stopper_tx, p2p_primary_stream_tx, from_listener);
    let sess = session;
    let mut state_container = inner_mut_state!(sess.state_container);
    // if this is called from a client-side connection, forcibly upgrade since the client asserts its connection is what will be used

    // call upgrade, and, load udp socket
    state_container
        .insert_direct_p2p_connection(direct_p2p_remote, v_conn.get_target_cid())
        .map_err(|err| generic_error(err.into_string()))?;
    HdpSession::udp_socket_loader(
        sess.clone(),
        v_conn,
        UdpSplittableTypes::Quic(udp_conn),
        hole_punched_addr,
        ticket,
        None,
    );

    std::mem::drop(state_container);

    let future = async move {
        let res = tokio::select! {
            res0 = writer_future => res0,
            res1 = reader_future => res1,
            res2 = stopper_future => res2
        };

        if let Err(err) = &res {
            log::error!(target: "citadel", "[P2P-stream] P2P stream ending. Reason: {}", err.to_string());
        }

        log::trace!(target: "citadel", "[P2P-stream] Dropping tri-joined future");
        res
    };

    spawn!(future);

    Ok(())
}

pub struct P2PInboundHandle {
    pub remote_peer: SocketAddr,
    pub local_bind_port: u16,
    // this has to be the CID of the local session, not the peer's CID
    pub implicated_cid: DualRwLock<Option<u64>>,
    pub kernel_tx: UnboundedSender<NodeResult>,
    pub to_primary_stream: OutboundPrimaryStreamSender,
}

impl P2PInboundHandle {
    fn new(
        remote_peer: SocketAddr,
        local_bind_port: u16,
        implicated_cid: DualRwLock<Option<u64>>,
        kernel_tx: UnboundedSender<NodeResult>,
        to_primary_stream: OutboundPrimaryStreamSender,
    ) -> Self {
        Self {
            remote_peer,
            local_bind_port,
            implicated_cid,
            kernel_tx,
            to_primary_stream,
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
#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "citadel", skip_all, ret, err, fields(implicated_cid=implicated_cid.get(), peer_cid=peer_connection_type.get_original_target_cid())))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn attempt_simultaneous_hole_punch(
    peer_connection_type: PeerConnectionType,
    ticket: Ticket,
    session: HdpSession,
    peer_nat_info: PeerNatInfo,
    implicated_cid: DualRwLock<Option<u64>>,
    kernel_tx: UnboundedSender<NodeResult>,
    channel_signal: NodeResult,
    sync_time: Instant,
    app: NetworkEndpoint,
    encrypted_config_container: HolePunchConfigContainer,
    client_config: Arc<rustls::ClientConfig>,
) -> std::io::Result<()> {
    let is_initiator = app.is_initiator();
    let kernel_tx = &kernel_tx;
    let v_conn = peer_connection_type.as_virtual_connection();

    let process = async move {
        tokio::time::sleep_until(sync_time).await;

        let hole_punched_socket = app
            .begin_udp_hole_punch(encrypted_config_container)
            .await
            .map_err(generic_error)?;
        let remote_connect_addr = hole_punched_socket.addr.send_address;
        let addr = hole_punched_socket.addr;
        let local_addr = hole_punched_socket.socket.local_addr()?;
        log::trace!(target: "citadel", "~!@ P2P UDP Hole-punch finished @!~ | is initiator: {}", is_initiator);

        app.sync().await.map_err(generic_error)?;
        // if local is NOT initiator, we setup a listener at the socket
        // if local IS the initiator, then start connecting. It should work
        if is_initiator {
            // give time for non-initiator to setup local bind
            tokio::time::sleep(Duration::from_millis(200)).await;
            let socket = hole_punched_socket.socket;
            let quic_endpoint =
                citadel_wire::quic::QuicClient::new_with_config(socket, client_config.clone())
                    .map_err(generic_error)?;
            let p2p_stream = Node::quic_p2p_connect_defaults(
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
                implicated_cid,
                session.clone(),
                kernel_tx.clone(),
                false,
                v_conn,
                addr,
                ticket,
            )
        } else {
            log::trace!(target: "citadel", "Non-initiator will begin listening immediately");
            std::mem::drop(hole_punched_socket); // drop to prevent conflicts caused by SO_REUSE_ADDR
            setup_listener_non_initiator(local_addr, remote_connect_addr, session.clone(), v_conn, addr, ticket)
                .await
                .map_err(|err|generic_error(format!("Non-initiator was unable to secure connection despite hole-punching success: {err:?}")))
        }
    };

    if let Err(err) = process.await {
        log::warn!(target: "citadel", "[Hole-punch/Err] {:?}", err);
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
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
