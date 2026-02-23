//! WebRTC connection helpers for WASM P2P.
//!
//! Provides functions to create `RtcPeerConnection`s with ICE configuration,
//! manage SDP offer/answer exchange, and wait for DataChannel readiness.
//!
//! All async operations use callback+oneshot patterns (no `wasm_bindgen_futures`
//! dependency) to match the existing WASM transport style.
#![allow(unsafe_code)]

use std::io;
use std::sync::Arc;

use citadel_io::tokio::sync::oneshot;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcDataChannelInit, RtcIceCandidate, RtcIceCandidateInit,
    RtcIceServer, RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcSessionDescriptionInit,
};

use super::wasm_io::IceServerConfig;
use crate::proto::peer::peer_crypt::IceCandidateData;

// ── Helpers ─────────────────────────────────────────────────────────

/// Await a JS `Promise` via callback+oneshot (avoids wasm_bindgen_futures).
async fn await_js_promise(promise: js_sys::Promise) -> io::Result<JsValue> {
    let (tx, rx) = oneshot::channel::<Result<JsValue, JsValue>>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    let tx_ok = tx.clone();
    let on_resolve = Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_ok.lock().unwrap().take() {
            let _ = tx.send(Ok(val));
        }
    });

    let tx_err = tx.clone();
    let on_reject = Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_err.lock().unwrap().take() {
            let _ = tx.send(Err(val));
        }
    });

    let _ = promise.then2(&on_resolve, &on_reject);

    // Keep closures alive until promise resolves
    let result = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "JS promise channel dropped"))?;

    drop(on_resolve);
    drop(on_reject);

    result.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))
}

fn js_err(e: JsValue) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
}

// ── Public API ──────────────────────────────────────────────────────

/// Create an `RtcPeerConnection` configured with the given ICE servers.
pub fn create_peer_connection(ice_servers: &[IceServerConfig]) -> io::Result<RtcPeerConnection> {
    let config = RtcConfiguration::new();
    let servers = js_sys::Array::new();

    for srv in ice_servers {
        let ice_server = RtcIceServer::new();
        let urls = js_sys::Array::new();
        for url in &srv.urls {
            urls.push(&JsValue::from_str(url));
        }
        ice_server.set_urls(&urls);
        if let Some(ref user) = srv.username {
            ice_server.set_username(user);
        }
        if let Some(ref cred) = srv.credential {
            ice_server.set_credential(cred);
        }
        servers.push(&ice_server);
    }
    config.set_ice_servers(&servers);

    RtcPeerConnection::new_with_configuration(&config).map_err(js_err)
}

/// Create an ordered, reliable DataChannel (TCP-like semantics).
pub fn create_reliable_data_channel(pc: &RtcPeerConnection, label: &str) -> RtcDataChannel {
    let init = RtcDataChannelInit::new();
    init.set_ordered(true);
    pc.create_data_channel_with_data_channel_dict(label, &init)
}

/// Wait until ICE gathering is complete, collecting all candidates.
async fn gather_ice_candidates(pc: &RtcPeerConnection) -> io::Result<Vec<IceCandidateData>> {
    let candidates = Arc::new(std::sync::Mutex::new(Vec::<IceCandidateData>::new()));
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let done_tx = Arc::new(std::sync::Mutex::new(Some(done_tx)));

    let cands = candidates.clone();
    let tx = done_tx.clone();
    let cb = Closure::wrap(Box::new(move |event: RtcPeerConnectionIceEvent| {
        if let Some(candidate) = event.candidate() {
            cands.lock().unwrap().push(IceCandidateData {
                candidate: candidate.candidate(),
                sdp_mid: candidate.sdp_mid(),
                sdp_mline_index: candidate.sdp_m_line_index(),
            });
        } else {
            // null candidate → gathering complete
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }) as Box<dyn FnMut(RtcPeerConnectionIceEvent)>);

    pc.set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
    let _ = done_rx.await;
    pc.set_onicecandidate(None);
    drop(cb);

    let result = candidates.lock().unwrap().clone();
    Ok(result)
}

/// Set local description on the peer connection.
async fn set_local_description(
    pc: &RtcPeerConnection,
    desc: &RtcSessionDescriptionInit,
) -> io::Result<()> {
    await_js_promise(pc.set_local_description(desc)).await?;
    Ok(())
}

/// Set remote description on the peer connection.
async fn set_remote_description(
    pc: &RtcPeerConnection,
    desc: &RtcSessionDescriptionInit,
) -> io::Result<()> {
    await_js_promise(pc.set_remote_description(desc)).await?;
    Ok(())
}

/// Add remote ICE candidates to the peer connection.
async fn add_ice_candidates(
    pc: &RtcPeerConnection,
    candidates: &[IceCandidateData],
) -> io::Result<()> {
    for cand in candidates {
        let init = RtcIceCandidateInit::new(&cand.candidate);
        if let Some(ref mid) = cand.sdp_mid {
            init.set_sdp_mid(Some(mid));
        }
        if let Some(idx) = cand.sdp_mline_index {
            init.set_sdp_m_line_index(Some(idx));
        }
        let ice = RtcIceCandidate::new(&init).map_err(js_err)?;
        await_js_promise(pc.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&ice))).await?;
    }
    Ok(())
}

// ── Offer / Answer ──────────────────────────────────────────────────

/// Create an SDP offer and gather all ICE candidates.
///
/// Returns `(sdp_offer, ice_candidates)`.
pub async fn create_offer_with_candidates(
    pc: &RtcPeerConnection,
) -> io::Result<(String, Vec<IceCandidateData>)> {
    let offer_js = await_js_promise(pc.create_offer()).await?;

    let offer_sdp = js_sys::Reflect::get(&offer_js, &JsValue::from_str("sdp"))
        .map_err(js_err)?
        .as_string()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "SDP offer not a string"))?;

    let desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    desc.set_sdp(&offer_sdp);
    set_local_description(pc, &desc).await?;

    let candidates = gather_ice_candidates(pc).await?;
    Ok((offer_sdp, candidates))
}

/// Accept a remote SDP offer, create an answer, and gather ICE candidates.
///
/// Returns `(sdp_answer, ice_candidates)`.
pub async fn accept_offer_with_candidates(
    pc: &RtcPeerConnection,
    remote_sdp: &str,
    remote_candidates: &[IceCandidateData],
) -> io::Result<(String, Vec<IceCandidateData>)> {
    let offer_desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    offer_desc.set_sdp(remote_sdp);
    set_remote_description(pc, &offer_desc).await?;

    add_ice_candidates(pc, remote_candidates).await?;

    let answer_js = await_js_promise(pc.create_answer()).await?;

    let answer_sdp = js_sys::Reflect::get(&answer_js, &JsValue::from_str("sdp"))
        .map_err(js_err)?
        .as_string()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "SDP answer not a string"))?;

    let desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    desc.set_sdp(&answer_sdp);
    set_local_description(pc, &desc).await?;

    let candidates = gather_ice_candidates(pc).await?;
    Ok((answer_sdp, candidates))
}

/// Apply a remote SDP answer and ICE candidates.
pub async fn apply_answer(
    pc: &RtcPeerConnection,
    remote_sdp: &str,
    remote_candidates: &[IceCandidateData],
) -> io::Result<()> {
    let desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    desc.set_sdp(remote_sdp);
    set_remote_description(pc, &desc).await?;
    add_ice_candidates(pc, remote_candidates).await?;
    Ok(())
}

// ── DataChannel readiness ───────────────────────────────────────────

/// Wait for a DataChannel to reach the `open` state.
pub async fn wait_for_datachannel_open(dc: &RtcDataChannel) -> io::Result<()> {
    if dc.ready_state() == web_sys::RtcDataChannelState::Open {
        return Ok(());
    }

    let (tx, rx) = oneshot::channel::<io::Result<()>>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    let tx_ok = tx.clone();
    let onopen = Closure::wrap(Box::new(move |_: web_sys::Event| {
        if let Some(tx) = tx_ok.lock().unwrap().take() {
            let _ = tx.send(Ok(()));
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    dc.set_onopen(Some(onopen.as_ref().unchecked_ref()));

    let tx_err = tx.clone();
    let onerror = Closure::wrap(Box::new(move |_: web_sys::Event| {
        if let Some(tx) = tx_err.lock().unwrap().take() {
            let _ = tx.send(Err(io::Error::new(
                io::ErrorKind::Other,
                "DataChannel error during open",
            )));
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    dc.set_onerror(Some(onerror.as_ref().unchecked_ref()));

    let result = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "DC open channel dropped"))?;

    dc.set_onopen(None);
    dc.set_onerror(None);
    drop(onopen);
    drop(onerror);

    result
}

/// Wait for the remote peer to create a DataChannel (responder side).
pub async fn wait_for_remote_datachannel(pc: &RtcPeerConnection) -> io::Result<RtcDataChannel> {
    let (tx, rx) = oneshot::channel::<RtcDataChannel>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    let cb = Closure::wrap(Box::new(move |event: web_sys::RtcDataChannelEvent| {
        if let Some(tx) = tx.lock().unwrap().take() {
            let _ = tx.send(event.channel());
        }
    }) as Box<dyn FnMut(web_sys::RtcDataChannelEvent)>);

    pc.set_ondatachannel(Some(cb.as_ref().unchecked_ref()));

    let dc = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "ondatachannel dropped"))?;

    pc.set_ondatachannel(None);
    drop(cb);

    Ok(dc)
}
