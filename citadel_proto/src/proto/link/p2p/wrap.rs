//! Seal: a P2P QUIC connection wrapped into the session's framing, bound to the P2P connection
//! the key exchange made (the first half of what `handle_p2p_stream` did). Nothing here touches
//! the connection's routing state; [`super::attach`] does, so a wrapped stream that is never
//! attached leaves nothing behind.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot::{channel, Receiver};
use citadel_types::prelude::{SessionSecuritySettings, UdpMode};
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;

use crate::functional::IfTrueConditional;
use crate::proto::misc;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::misc::udp_internal_interface::QuicUdpSocketConnector;
use crate::proto::node_result::NodeResult;
use crate::proto::outbound_budget::MAX_QUEUED_OUTBOUND_BYTES;
use crate::proto::outbound_sender::{
    budgeted_primary_channel, OutboundPrimaryStreamReceiver, UnboundedSender,
};
use crate::proto::packet::HeaderObfuscator;
use crate::proto::peer::p2p_conn_handler::{generic_error, DirectP2PRemote, P2PInboundHandle};
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualConnectionType;
use crate::proto::traffic::meter::{RouteMeter, StreamMeter};

/// What the seal step needs to know about the route it wraps.
pub(crate) struct RouteFacts {
    /// The route's id among every route this node attaches (`next_route_id`).
    pub(crate) route_id: u64,
    pub(crate) from_listener: bool,
    pub(crate) v_conn: VirtualConnectionType,
    pub(crate) hole_punched_addr: TargettedSocketAddr,
    pub(crate) ticket: Ticket,
    pub(crate) udp_mode: UdpMode,
    pub(crate) session_security_settings: SessionSecuritySettings,
    pub(crate) path: P2pRoute,
}

/// A wrapped P2P stream, ready to be attached. Dropping it closes the stream.
pub(crate) struct WrappedP2pStream<R: Ratchet, T: PlatformOps> {
    pub(crate) session: CitadelSession<R, T>,
    pub(crate) facts: RouteFacts,
    pub(crate) peer_cid: u64,
    pub(crate) session_cid: DualRwLock<Option<u64>>,
    pub(crate) kernel_tx: UnboundedSender<NodeResult<R>>,
    /// The P2P connection this route is bound to (`Ticket(0)` when none existed to bind to;
    /// the attach then refuses it).
    pub(crate) connection_id: Ticket,
    pub(crate) sink: misc::PrimaryStreamWriter<GenericNetworkStream>,
    pub(crate) stream: misc::PrimaryStreamReader<GenericNetworkStream>,
    pub(crate) primary_rx: OutboundPrimaryStreamReceiver,
    pub(crate) header_obfuscator: HeaderObfuscator,
    pub(crate) meter: StreamMeter,
    pub(crate) route_meter: RouteMeter,
    pub(crate) udp_conn: QuicUdpSocketConnector,
    pub(crate) inbound_handle: P2PInboundHandle<R>,
    pub(crate) remote: DirectP2PRemote,
    pub(crate) stopper_rx: Receiver<()>,
}

/// Wraps `p2p_stream` for the P2P connection to `facts.v_conn`'s peer.
pub(crate) fn wrap_p2p_stream<R: Ratchet, T: PlatformOps>(
    mut p2p_stream: GenericNetworkStream,
    session_cid: DualRwLock<Option<u64>>,
    session: CitadelSession<R, T>,
    kernel_tx: UnboundedSender<NodeResult<R>>,
    facts: RouteFacts,
) -> std::io::Result<WrappedP2pStream<R, T>> {
    let remote_peer = p2p_stream.peer_addr()?;
    let local_bind_addr = p2p_stream.local_addr()?;
    let from_listener = facts.from_listener;
    // Only this connection's client can migrate, and not through its own TURN allocation.
    let migratable = !from_listener && facts.path != (P2pRoute::Turn { relayed_both: true });
    if let Some(endpoint) = p2p_stream.p2p_endpoint().filter(|_| migratable) {
        session
            .session_manager
            .local_rebinder()
            .track_quic_client(endpoint);
    }
    let quic_conn = p2p_stream
        .take_p2p_connection()
        .ok_or_else(|| generic_error("P2P Stream did not have QUIC connection loaded"))?;
    let udp_conn = QuicUdpSocketConnector::new(quic_conn, local_bind_addr);

    log::trace!(target: "citadel", "[P2P-stream {}] New stream from {:?}", from_listener.if_true("listener").if_false("client"), remote_peer);
    let (sink, stream) = misc::safe_split_stream(p2p_stream);
    let (primary_tx, primary_rx) = budgeted_primary_channel(MAX_QUEUED_OUTBOUND_BYTES, None);
    let header_obfuscator = HeaderObfuscator::new(
        from_listener,
        facts.session_security_settings.header_obfuscator_settings,
    );
    let peer_cid = facts.v_conn.get_target_cid();
    let (connection_id, connection_bytes) = {
        let state = inner_state!(session.state_container);
        let vconn = state.active_virtual_connections.get(&peer_cid);
        let bytes = vconn
            .and_then(|vconn| vconn.endpoint_container.as_ref())
            .map(|endpoint| endpoint.p2p_path.byte_counters().clone());
        (
            vconn
                .map(|vconn| vconn.p2p_connection_id)
                .unwrap_or(Ticket(0)),
            bytes,
        )
    };
    // Without a virtual connection the route is refused when attached (it has nothing to
    // attach to); its few packets until then still count toward the node's totals.
    let route_meter = RouteMeter::new(
        connection_bytes.unwrap_or_default(),
        session.session_manager.traffic(),
        facts.path,
    );
    let meter = StreamMeter::Route(route_meter.clone());
    let inbound_handle = P2PInboundHandle::new(
        remote_peer,
        local_bind_addr.port(),
        session_cid.clone(),
        kernel_tx.clone(),
        primary_tx.clone(),
        peer_cid,
        connection_id,
    );
    let (stopper_tx, stopper_rx) = channel();
    let remote = DirectP2PRemote::new(stopper_tx, primary_tx, from_listener, facts.route_id);
    Ok(WrappedP2pStream {
        session,
        facts,
        peer_cid,
        session_cid,
        kernel_tx,
        connection_id,
        sink,
        stream,
        primary_rx,
        header_obfuscator,
        meter,
        route_meter,
        udp_conn,
        inbound_handle,
        remote,
        stopper_rx,
    })
}
