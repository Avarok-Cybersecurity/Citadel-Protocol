//! WebRTC DataChannel P2P hole punch for WASM targets.
//!
//! Implements `PlatformOps::p2p_hole_punch` using WebRTC DataChannels
//! for browser-to-browser P2P connections. The signaling (SDP + ICE)
//! is relayed through the Citadel server via `PeerSignal::WebRtcSignaling`.
#![allow(unsafe_code)]

use super::wasm_io::{IceServerConfig, WasmIO};
use super::wasm_stream::{SendFuture, WasmDataChannelStream};
use crate::proto::peer::peer_crypt::WebRtcSignalingPayload;

// ── WebRTC hole punch helpers ────────────────────────────────────────

/// Initiator: create offer, send it, wait for answer, open DataChannel.
async fn hole_punch_initiator(
    ice_servers: &[IceServerConfig],
    send_signaling: &dyn Fn(WebRtcSignalingPayload) -> Result<(), crate::error::NetworkError>,
    sig_rx: &mut citadel_io::tokio::sync::mpsc::UnboundedReceiver<WebRtcSignalingPayload>,
) -> std::io::Result<(
    web_sys::RtcDataChannel,
    std::sync::Arc<web_sys::RtcPeerConnection>,
)> {
    use super::wasm_rtc;

    let pc = wasm_rtc::create_peer_connection(ice_servers)?;
    let dc = wasm_rtc::create_reliable_data_channel(&pc, "citadel");
    let (offer_sdp, offer_candidates) = wasm_rtc::create_offer_with_candidates(&pc).await?;

    send_signaling(WebRtcSignalingPayload::Offer {
        sdp: offer_sdp,
        ice_candidates: offer_candidates,
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let answer = sig_rx.recv().await.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "signaling channel closed",
        )
    })?;

    match answer {
        WebRtcSignalingPayload::Answer {
            sdp,
            ice_candidates,
        } => {
            wasm_rtc::apply_answer(&pc, &sdp, &ice_candidates).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected Answer, got Offer",
            ));
        }
    }

    wasm_rtc::wait_for_datachannel_open(&dc).await?;
    Ok((dc, std::sync::Arc::new(pc)))
}

/// Responder: wait for offer, create answer, send it, accept DataChannel.
async fn hole_punch_responder(
    ice_servers: &[IceServerConfig],
    send_signaling: &dyn Fn(WebRtcSignalingPayload) -> Result<(), crate::error::NetworkError>,
    sig_rx: &mut citadel_io::tokio::sync::mpsc::UnboundedReceiver<WebRtcSignalingPayload>,
) -> std::io::Result<(
    web_sys::RtcDataChannel,
    std::sync::Arc<web_sys::RtcPeerConnection>,
)> {
    use super::wasm_rtc;

    let offer = sig_rx.recv().await.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "signaling channel closed",
        )
    })?;

    let (remote_sdp, remote_candidates) = match offer {
        WebRtcSignalingPayload::Offer {
            sdp,
            ice_candidates,
        } => (sdp, ice_candidates),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected Offer, got Answer",
            ));
        }
    };

    let pc = wasm_rtc::create_peer_connection(ice_servers)?;
    let (answer_sdp, answer_candidates) =
        wasm_rtc::accept_offer_with_candidates(&pc, &remote_sdp, &remote_candidates).await?;

    send_signaling(WebRtcSignalingPayload::Answer {
        sdp: answer_sdp,
        ice_candidates: answer_candidates,
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let dc = wasm_rtc::wait_for_remote_datachannel(&pc).await?;
    wasm_rtc::wait_for_datachannel_open(&dc).await?;
    Ok((dc, std::sync::Arc::new(pc)))
}

// ── PlatformOps impl ────────────────────────────────────────────────

impl super::platform_ops::PlatformOps for WasmIO {
    #[allow(clippy::too_many_arguments)]
    fn p2p_hole_punch<R: citadel_crypt::ratchets::Ratchet>(
        session: crate::proto::session::CitadelSession<R, Self>,
        peer_connection_type: crate::proto::peer::peer_layer::PeerConnectionType,
        ticket: crate::proto::remote::Ticket,
        peer_nat_info: crate::proto::peer::peer_crypt::PeerNatInfo,
        channel_signal: crate::proto::node_result::NodeResult<R>,
        hole_punch_compat_stream: crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream<R>,
        endpoint_ratchet: R,
        peer_cid: u64,
        sync_instant: citadel_io::time::Instant,
        node_type: netbeam::sync::RelativeNodeType,
        udp_mode: citadel_types::proto::UdpMode,
        session_security_settings: citadel_types::proto::SessionSecuritySettings,
        cancel_rx: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::NetworkError>>
           + crate::macros::ContextRequirements {
        use crate::proto::peer::peer_layer::PeerSignal;

        SendFuture(async move {
            let _ = (
                peer_nat_info,
                hole_punch_compat_stream,
                endpoint_ratchet,
                sync_instant,
                udp_mode,
                cancel_rx,
            );

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
                        .map_err(|e| crate::error::NetworkError::generic(e.into_string()))?;
                    session.send_to_primary_stream(Some(ticket), packet)?;
                    Ok(())
                };

            let result = if is_initiator {
                hole_punch_initiator(&ice_servers, &send_signaling, &mut sig_rx).await
            } else {
                hole_punch_responder(&ice_servers, &send_signaling, &mut sig_rx).await
            };

            // Clean up signaling channel
            {
                let mut state = inner_mut_state!(session.state_container);
                state.webrtc_signaling_channels.remove(&peer_cid);
            }

            match result {
                Ok((dc, pc)) => {
                    on_datachannel_established::<R, Self>(
                        session,
                        dc,
                        pc,
                        peer_cid,
                        is_initiator,
                        session_security_settings,
                        channel_signal,
                    )?;
                    Ok(())
                }
                Err(err) => {
                    log::warn!(target: "citadel", "WebRTC hole punch failed: {err}, falling back to relay");
                    session.send_to_kernel(channel_signal)?;
                    Ok(())
                }
            }
        })
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
                pre_built_stream: Some(stream_holder),
            };
            (None, Some(cfg), crate::prelude::NodeType::Peer)
        }
    }
}

/// Register the established DataChannel as a P2P stream and start the pump.
fn on_datachannel_established<
    R: citadel_crypt::ratchets::Ratchet,
    T: super::platform_ops::PlatformOps,
>(
    session: crate::proto::session::CitadelSession<R, T>,
    dc: web_sys::RtcDataChannel,
    pc: std::sync::Arc<web_sys::RtcPeerConnection>,
    peer_cid: u64,
    is_initiator: bool,
    session_security_settings: citadel_types::proto::SessionSecuritySettings,
    channel_signal: crate::proto::node_result::NodeResult<R>,
) -> Result<(), crate::error::NetworkError> {
    let stream = super::wasm_stream::WasmStream::DataChannel(WasmDataChannelStream::new(dc, pc));
    let (sink, source) = super::safe_split_stream(stream);
    let (p2p_tx, p2p_rx) = crate::proto::outbound_sender::unbounded();
    let p2p_tx = crate::proto::outbound_sender::OutboundPrimaryStreamSender::from(p2p_tx);
    let p2p_rx = crate::proto::outbound_sender::OutboundPrimaryStreamReceiver::from(p2p_rx);

    let direct_p2p_remote = crate::proto::peer::p2p_conn_handler::DirectP2PRemote {
        stopper: None,
        p2p_primary_stream: p2p_tx.clone(),
        from_listener: !is_initiator,
    };
    let session_cid_val = session.session_cid.get().unwrap_or(0);

    {
        let mut state = inner_mut_state!(session.state_container);
        state.insert_direct_p2p_connection(direct_p2p_remote, peer_cid, session_cid_val, None)?;
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
        if let Some(ratchet) = state
            .active_virtual_connections
            .get(&peer_cid)
            .and_then(|v| v.get_endpoint_ratchet(None))
        {
            state.stale_p2p_ratchets.insert(peer_cid, ratchet);
        }
        state.active_virtual_connections.remove(&peer_cid);
    });

    session.send_to_kernel(channel_signal)?;
    Ok(())
}
