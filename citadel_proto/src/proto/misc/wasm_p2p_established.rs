//! Post-handshake registration of WASM WebRTC DataChannels with the session. Split out of
//! `wasm_p2p.rs` (exact piecewise copy) to respect the file-size limit.
#![allow(unsafe_code)]

use super::wasm_p2p_signaling::EstablishedChannels;
use super::wasm_stream::WasmDataChannelStream;

/// Register the established DataChannel as a P2P stream and start the pump. When the unordered
/// channel also opened, wire it into the UDP subsystem exactly as the native path does after a
/// successful hole punch.
#[allow(clippy::too_many_arguments)]
pub(super) fn on_datachannel_established<
    R: citadel_crypt::ratchets::Ratchet,
    T: super::platform_ops::PlatformOps,
>(
    session: crate::proto::session::CitadelSession<R, T>,
    channels: EstablishedChannels,
    peer_cid: u64,
    ticket: crate::proto::remote::Ticket,
    is_initiator: bool,
    session_security_settings: citadel_types::proto::SessionSecuritySettings,
) -> Result<(), crate::error::NetworkError> {
    let EstablishedChannels {
        reliable: dc,
        unreliable: udp_dc,
        pc,
    } = channels;
    let stream = super::wasm_stream::WasmStream::DataChannel(WasmDataChannelStream::new(dc, pc));
    let (sink, source) = super::safe_split_stream(stream);
    let (p2p_tx, p2p_rx) = crate::proto::outbound_sender::unbounded();
    let p2p_tx = crate::proto::outbound_sender::OutboundPrimaryStreamSender::from(p2p_tx);
    let p2p_rx = crate::proto::outbound_sender::OutboundPrimaryStreamReceiver::from(p2p_rx);

    let route_id = crate::proto::peer::p2p_conn_handler::next_route_id();
    let direct_p2p_remote = crate::proto::peer::p2p_conn_handler::DirectP2PRemote {
        stopper: None,
        p2p_primary_stream: p2p_tx.clone(),
        from_listener: !is_initiator,
        route_id,
    };
    let session_cid_val = session.session_cid.get().unwrap_or(0);

    {
        let mut state = inner_mut_state!(session.state_container);
        state.insert_direct_p2p_connection(direct_p2p_remote, peer_cid, session_cid_val, None)?;
        if let Some(endpoint) = state
            .active_virtual_connections
            .get(&peer_cid)
            .and_then(|vconn| vconn.endpoint_container.as_ref())
        {
            endpoint
                .p2p_path
                .set(crate::proto::peer::p2p_path::P2pRoute::Direct);
        }
    }

    let header_obfuscator = crate::proto::packet::HeaderObfuscator::new(
        !is_initiator,
        session_security_settings.header_obfuscator_settings,
    );
    let p2p_handle = crate::proto::peer::p2p_conn_handler::P2PInboundHandle::new(
        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        0,
        session.session_cid.clone(),
        session.kernel_tx.clone(),
        p2p_tx,
        peer_cid,
    );
    let writer = crate::proto::session::CitadelSession::<R, T>::outbound_stream(
        p2p_rx,
        sink,
        header_obfuscator.clone(),
    );
    let reader = crate::proto::session::CitadelSession::execute_inbound_stream(
        source,
        session.clone(),
        Some(p2p_handle),
        header_obfuscator,
    );

    let sess = session.clone();
    spawn!(async move {
        let res = citadel_io::tokio::select! {
            r0 = writer => r0,
            r1 = reader => r1,
        };
        if let Err(err) = &res {
            log::error!(target: "citadel", "[WebRTC P2P] stream ending: {err}");
        }
        let mut state = inner_mut_state!(sess.state_container);
        // A live connection outlives its DataChannel: it falls back to the server relay.
        if state.fall_back_to_server_relay(peer_cid, route_id)
            != crate::proto::state_container::RouteEnd::ConnectionClosed
        {
            return;
        }
        if let Some(ratchet) = state
            .active_virtual_connections
            .get(&peer_cid)
            .and_then(|v| v.get_endpoint_ratchet(None))
        {
            state.stale_p2p_ratchets.insert(peer_cid, ratchet);
        }
        state.active_virtual_connections.remove(&peer_cid);
    });

    if let Some(udp_dc) = udp_dc {
        use super::udp_internal_interface::{UdpSplittableTypes, WebRtcDataChannelConnector};
        use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
        let sentinel = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
        let peer_addr = TargettedSocketAddr::new_invariant(sentinel);
        let conn = UdpSplittableTypes::WebRtc(WebRtcDataChannelConnector::new(
            udp_dc, sentinel, peer_addr,
        ));
        let v_target = crate::proto::state_container::VirtualConnectionType::LocalGroupPeer {
            session_cid: session_cid_val,
            peer_cid,
        };
        T::spawn_udp_socket_loader(session.clone(), v_target, conn, peer_addr, ticket, None);
    }

    Ok(())
}
