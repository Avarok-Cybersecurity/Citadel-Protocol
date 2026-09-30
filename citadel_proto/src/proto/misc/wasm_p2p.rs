//! WebRTC DataChannel P2P hole punch for WASM targets.
//!
//! Implements `PlatformOps::p2p_hole_punch` using WebRTC DataChannels
//! for browser-to-browser P2P connections. The signaling (SDP + ICE)
//! is relayed through the Citadel server via `PeerSignal::WebRtcSignaling`.
#![allow(unsafe_code)]

use super::wasm_io::WasmIO;
use super::wasm_p2p_established::on_datachannel_established;
use super::wasm_p2p_signaling::{hole_punch_initiator, hole_punch_responder};
use super::wasm_stream::SendFuture;
use crate::proto::peer::peer_crypt::WebRtcSignalingPayload;

// ── PlatformOps impl ────────────────────────────────────────────────

impl super::platform_ops::PlatformOps for WasmIO {
    #[allow(clippy::too_many_arguments)]
    fn p2p_hole_punch<R: citadel_crypt::ratchets::Ratchet>(
        session: crate::proto::session::CitadelSession<R, Self>,
        peer_connection_type: crate::proto::peer::peer_layer::PeerConnectionType,
        ticket: crate::proto::remote::Ticket,
        peer_nat_info: crate::proto::peer::peer_crypt::PeerNatInfo,
        app: netbeam::sync::network_endpoint::NetworkEndpoint,
        endpoint_ratchet: R,
        peer_cid: u64,
        sync_instant: citadel_io::time::Instant,
        node_type: netbeam::sync::RelativeNodeType,
        udp_mode: citadel_types::proto::UdpMode,
        session_security_settings: citadel_types::proto::SessionSecuritySettings,
        plan: crate::proto::peer::p2p_path::P2pPlan,
    ) -> impl std::future::Future<Output = bool> + crate::macros::ContextRequirements {
        use crate::proto::peer::peer_layer::PeerSignal;

        SendFuture(async move {
            // The browser's ICE agent owns relaying (its TURN servers come from the node's
            // `with_turn_servers`); the native TURN plan does not apply here. The ICE exchange
            // rides its own signaling, so the registered endpoint is not needed either.
            let _ = (peer_nat_info, app, endpoint_ratchet, sync_instant, plan);

            let is_initiator = node_type == netbeam::sync::RelativeNodeType::Initiator;
            let ice_servers = session.p2p_ice_servers();

            // Register signaling channel for this peer
            let (sig_tx, mut sig_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
            {
                let mut state = inner_mut_state!(session.state_container);
                state.webrtc_signaling_channels.insert(peer_cid, sig_tx);
            }

            let send_signaling =
                |payload: WebRtcSignalingPayload| -> Result<(), crate::error::NetworkError> {
                    let signal = PeerSignal::WebRtcSignaling {
                        peer_conn_type: peer_connection_type.clone(),
                        payload,
                    };
                    let accessor =
                        crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor::C2S(
                            session.state_container.clone(),
                        );
                    let timestamp = session.time_tracker.get_global_time_ns();
                    let security_level = citadel_types::crypto::SecurityLevel::Standard;
                    let packet = accessor
                        .borrow_hr(None, |hr, _| {
                            crate::proto::packet_crafter::peer_cmd::craft_peer_signal(
                                hr,
                                signal,
                                ticket,
                                timestamp,
                                security_level,
                            )
                        })
                        .map_err(|e| crate::error::NetworkError::generic(e.into_string()))??;
                    session.send_to_primary_stream(Some(ticket), packet)?;
                    Ok(())
                };

            let result = if is_initiator {
                hole_punch_initiator(&ice_servers, &send_signaling, &mut sig_rx, udp_mode).await
            } else {
                hole_punch_responder(&ice_servers, &send_signaling, &mut sig_rx, udp_mode).await
            };

            // Clean up signaling channel
            {
                let mut state = inner_mut_state!(session.state_container);
                state.webrtc_signaling_channels.remove(&peer_cid);
            }

            match result {
                Ok(channels) => match on_datachannel_established::<R, Self>(
                    session,
                    channels,
                    peer_cid,
                    ticket,
                    is_initiator,
                    session_security_settings,
                ) {
                    Ok(()) => true,
                    Err(err) => {
                        log::warn!(target: "citadel", "WebRTC DataChannel could not be attached: {err}; staying on the relay");
                        false
                    }
                },
                Err(err) => {
                    log::warn!(target: "citadel", "WebRTC hole punch failed: {err}; staying on the relay");
                    false
                }
            }
        })
    }

    fn spawn_udp_socket_loader<R: citadel_crypt::ratchets::Ratchet>(
        session: crate::proto::session::CitadelSession<R, Self>,
        v_target: crate::proto::state_container::VirtualTargetType,
        udp_conn: super::udp_internal_interface::UdpSplittableTypes,
        addr: citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr,
        ticket: crate::proto::remote::Ticket,
        tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) {
        super::udp_session_loader::spawn(
            session,
            v_target,
            udp_conn,
            addr,
            ticket,
            tcp_conn_awaiter,
        );
    }

    fn setup_serverless_transport(
        stream: super::wasm_stream::WasmStream,
        is_server_role: bool,
        existing_client_config: Option<super::wasm_io::WasmClientConfig>,
    ) -> (
        Option<super::wasm_io::WasmListener>,
        Option<super::wasm_io::WasmClientConfig>,
        crate::prelude::NodeType,
    ) {
        if is_server_role {
            let (tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
            let sentinel = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            let _ = tx.send(Ok((stream, sentinel)));
            let listener =
                super::wasm_io::WasmListener::Rtc(super::wasm_io::WasmRtcListener { rx });
            (
                Some(listener),
                existing_client_config,
                crate::prelude::NodeType::Server(sentinel),
            )
        } else {
            let stream_holder = std::sync::Arc::new(std::sync::Mutex::new(Some(stream)));
            let cfg = super::wasm_io::WasmClientConfig {
                use_tls: false,
                endpoint: None,
                pre_built_stream: Some(stream_holder),
            };
            (None, Some(cfg), crate::prelude::NodeType::Peer)
        }
    }
}
