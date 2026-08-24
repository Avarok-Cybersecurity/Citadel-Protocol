//! WebRTC SDP/ICE signaling legs of the WASM P2P hole punch. Split out of `wasm_p2p.rs`
//! (exact piecewise copy) to respect the file-size limit.
//!
//! When `udp_mode` is enabled both legs also open the pre-negotiated unordered DataChannel that
//! backs the UDP subsystem; its failure is non-fatal (the peer link simply runs TCP-only).

use super::wasm_io::IceServerConfig;
use super::wasm_rtc;
use crate::proto::peer::peer_crypt::WebRtcSignalingPayload;
use citadel_types::proto::UdpMode;
use std::sync::Arc;
use web_sys::{RtcDataChannel, RtcPeerConnection};

/// Bound on how long the unordered DataChannel may take to open after the reliable one did.
const UDP_DATACHANNEL_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) struct EstablishedChannels {
    pub reliable: RtcDataChannel,
    pub unreliable: Option<RtcDataChannel>,
    pub pc: Arc<RtcPeerConnection>,
}

fn maybe_create_udp_channel(pc: &RtcPeerConnection, udp_mode: UdpMode) -> Option<RtcDataChannel> {
    match udp_mode {
        UdpMode::Enabled => Some(wasm_rtc::create_unreliable_data_channel(pc)),
        UdpMode::Disabled => None,
    }
}

async fn await_udp_channel_open(udp_dc: Option<RtcDataChannel>) -> Option<RtcDataChannel> {
    let dc = udp_dc?;
    match citadel_io::time::timeout(
        UDP_DATACHANNEL_OPEN_TIMEOUT,
        wasm_rtc::wait_for_datachannel_open(&dc),
    )
    .await
    {
        Ok(Ok(())) => Some(dc),
        Ok(Err(err)) => {
            log::warn!(target: "citadel", "WebRTC UDP DataChannel failed to open ({err}); continuing TCP-only");
            None
        }
        Err(_) => {
            log::warn!(target: "citadel", "WebRTC UDP DataChannel open timed out; continuing TCP-only");
            None
        }
    }
}

/// Initiator: create offer, send it, wait for answer, open DataChannel(s).
pub(super) async fn hole_punch_initiator(
    ice_servers: &[IceServerConfig],
    send_signaling: &dyn Fn(WebRtcSignalingPayload) -> Result<(), crate::error::NetworkError>,
    sig_rx: &mut citadel_io::tokio::sync::mpsc::UnboundedReceiver<WebRtcSignalingPayload>,
    udp_mode: UdpMode,
) -> std::io::Result<EstablishedChannels> {
    let pc = wasm_rtc::create_peer_connection(ice_servers)?;
    let dc = wasm_rtc::create_reliable_data_channel(&pc, "citadel");
    // Created before the offer so the SCTP association is negotiated once for both channels.
    let udp_dc = maybe_create_udp_channel(&pc, udp_mode);
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
    let unreliable = await_udp_channel_open(udp_dc).await;
    Ok(EstablishedChannels {
        reliable: dc,
        unreliable,
        pc: Arc::new(pc),
    })
}

/// Responder: wait for offer, create answer, send it, accept DataChannel(s).
pub(super) async fn hole_punch_responder(
    ice_servers: &[IceServerConfig],
    send_signaling: &dyn Fn(WebRtcSignalingPayload) -> Result<(), crate::error::NetworkError>,
    sig_rx: &mut citadel_io::tokio::sync::mpsc::UnboundedReceiver<WebRtcSignalingPayload>,
    udp_mode: UdpMode,
) -> std::io::Result<EstablishedChannels> {
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
    let udp_dc = maybe_create_udp_channel(&pc, udp_mode);
    let (answer_sdp, answer_candidates) =
        wasm_rtc::accept_offer_with_candidates(&pc, &remote_sdp, &remote_candidates).await?;

    send_signaling(WebRtcSignalingPayload::Answer {
        sdp: answer_sdp,
        ice_candidates: answer_candidates,
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let dc = wasm_rtc::wait_for_remote_datachannel(&pc).await?;
    wasm_rtc::wait_for_datachannel_open(&dc).await?;
    let unreliable = await_udp_channel_open(udp_dc).await;
    Ok(EstablishedChannels {
        reliable: dc,
        unreliable,
        pc: Arc::new(pc),
    })
}
