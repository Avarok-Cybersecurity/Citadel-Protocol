//! Deliver: a wrapped P2P route attached to its connection (the second half of what
//! `handle_p2p_stream` did): the CID tiebreak of `insert_direct_p2p_connection`, the path cell,
//! the UDP loader, the task that reports the connection's end to the kernel, and the task that
//! carries the stream and falls back to the relay when it ends.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot::channel;
use citadel_types::prelude::UdpMode;

use super::disconnect_task::{report_disconnects, DisconnectReport};
use super::stream_end::{carry_stream, CarriedStream};
use super::wrap::WrappedP2pStream;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::misc::udp_internal_interface::UdpSplittableTypes;
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::P2PDisconnectSignal;

/// Attaches `wrapped` as its connection's direct (or TURN) route. Refused, with nothing left
/// behind, when the connection it was bound to no longer exists.
pub(crate) fn attach_p2p_stream<R: Ratchet, T: PlatformOps>(
    wrapped: WrappedP2pStream<R, T>,
) -> std::io::Result<()> {
    let WrappedP2pStream {
        session: sess,
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
    } = wrapped;
    let implcid = session_cid.get().unwrap_or(0);
    let writer_future = CitadelSession::<R, T>::outbound_stream(
        primary_rx,
        sink,
        header_obfuscator.clone(),
        meter.clone(),
    );
    let reader_future = CitadelSession::execute_inbound_stream(
        stream,
        sess.clone(),
        Some(inbound_handle),
        header_obfuscator,
        meter,
    );
    let route_id = remote.route_id;
    let (p2p_dc_tx, p2p_dc_rx) = channel::<P2PDisconnectSignal>();

    let mut state_container = inner_mut_state!(sess.state_container);
    state_container
        .insert_direct_p2p_connection(remote, peer_cid, implcid, Some(p2p_dc_tx))
        .map_err(|err| generic_error(err.into_string()))?;

    if let Some(endpoint) = state_container
        .active_virtual_connections
        .get(&peer_cid)
        .and_then(|vconn| vconn.endpoint_container.as_ref())
    {
        let is_current = endpoint
            .direct_p2p_remote
            .as_ref()
            .is_some_and(|remote| remote.route_id == route_id);
        if is_current {
            endpoint.p2p_path.set(facts.path);
        }
    }

    if facts.udp_mode == UdpMode::Enabled {
        T::spawn_udp_socket_loader(
            sess.clone(),
            facts.v_conn,
            UdpSplittableTypes::Quic(udp_conn.metered(route_meter)),
            facts.hole_punched_addr,
            facts.ticket,
            None,
        );
    }

    // Taken now, not when the stream ends: by then the connection's state may be gone. It
    // holds the reason the peer gives on its lane for closing this connection.
    let peer_closing = state_container.peer_closing_of(peer_cid, Some(connection_id));
    drop(state_container);

    sess.session_manager
        .disconnect_tracker()
        .clear_p2p_peer(sess.kernel_ticket.get(), peer_cid);

    report_disconnects(DisconnectReport {
        session: sess.clone(),
        session_cid,
        kernel_tx,
        peer_closing,
        signal: p2p_dc_rx,
    });
    carry_stream(CarriedStream {
        session: sess,
        peer_cid,
        route_id,
        connection_id,
        writer: writer_future,
        reader: reader_future,
        stopper: stopper_rx,
    });
    Ok(())
}
