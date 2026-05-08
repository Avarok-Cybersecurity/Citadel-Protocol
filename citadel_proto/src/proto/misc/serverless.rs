//! Serverless connection orchestrator for browser-to-browser mode.
//!
//! Performs the full signaling flow: peer discovery, deterministic role
//! assignment, WebRTC offer/answer exchange, and DataChannel setup.
//! Returns a [`ServerlessConnection`] with the established stream and
//! the assigned role.

use std::io;
use std::sync::Arc;

use super::signaling::{
    compute_identity_hash, derive_room_id, determine_is_server, HelloMessage, SdpExchange,
    SignalingService,
};
use super::wasm_io::IceServerConfig;
use super::wasm_rtc::{
    accept_offer_with_candidates, apply_answer, create_offer_with_candidates,
    create_peer_connection, create_reliable_data_channel, wait_for_datachannel_open,
    wait_for_remote_datachannel,
};
use super::wasm_stream::{WasmDataChannelStream, WasmStream};

/// Configuration for a serverless browser-to-browser connection.
pub struct ServerlessConfig {
    /// Signaling backend (e.g., Firebase RTDB).
    pub signaling: Box<dyn SignalingService>,
    /// Shared token that both peers know. Determines the signaling room.
    pub room_token: Vec<u8>,
    /// ICE servers for WebRTC (STUN/TURN).
    pub ice_servers: Vec<IceServerConfig>,
    /// How often to poll the signaling service (milliseconds).
    pub poll_interval_ms: u64,
    /// Maximum time to wait for peer discovery (milliseconds).
    pub timeout_ms: u64,
}

impl ServerlessConfig {
    pub fn new(
        signaling: Box<dyn SignalingService>,
        room_token: &[u8],
        ice_servers: Vec<IceServerConfig>,
    ) -> Self {
        Self {
            signaling,
            room_token: room_token.to_vec(),
            ice_servers,
            poll_interval_ms: 500,
            timeout_ms: 30_000,
        }
    }
}

/// Result of the serverless connection setup.
pub struct ServerlessConnection {
    /// The established DataChannel stream.
    pub stream: WasmStream,
    /// `true` if this peer was assigned the server (Alpha) role.
    pub is_server_role: bool,
}

/// Generate a 32-byte random nonce using the browser's crypto API.
fn generate_nonce() -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 32];
    let crypto = web_sys::window()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no global window"))?
        .crypto()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
    crypto
        .get_random_values_with_u8_array(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
    Ok(buf)
}

/// Full signaling flow: discovery, role assignment, WebRTC, DataChannel.
pub async fn establish_serverless_connection(
    signaling: &dyn SignalingService,
    room_token: &[u8],
    ice_servers: &[IceServerConfig],
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> io::Result<ServerlessConnection> {
    let room = derive_room_id(room_token);

    // Step 1: Generate nonce and compute identity hash.
    let nonce = generate_nonce()?;
    let my_hash = compute_identity_hash(&nonce, room_token);

    // Step 2: Publish our HelloMessage.
    let hello = HelloMessage {
        identity_hash: my_hash.clone(),
        nonce: nonce.clone(),
    };
    let hello_value = serde_json::to_value(&hello)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let participant_key = &my_hash[..16];
    signaling
        .publish(
            &room.0,
            &format!("participants/{participant_key}"),
            hello_value,
        )
        .await?;

    // Step 3: Poll until we see 2 participants (or timeout).
    let their_hash =
        poll_for_peer(signaling, &room.0, &my_hash, poll_interval_ms, timeout_ms).await?;

    // Step 4: Determine role.
    let is_server = determine_is_server(&my_hash, &their_hash);
    log::trace!(target: "citadel", "Serverless role: {}", if is_server { "server (Alpha)" } else { "client (Beta)" });

    // Step 5: WebRTC offer/answer exchange.
    let stream = if is_server {
        alpha_flow(
            signaling,
            &room.0,
            ice_servers,
            poll_interval_ms,
            timeout_ms,
        )
        .await?
    } else {
        beta_flow(
            signaling,
            &room.0,
            ice_servers,
            poll_interval_ms,
            timeout_ms,
        )
        .await?
    };

    // Step 6: Clean up signaling room (best-effort).
    let _ = signaling.delete_room(&room.0).await;

    Ok(ServerlessConnection {
        stream,
        is_server_role: is_server,
    })
}

/// Poll participants until a second peer appears. Returns their identity hash.
async fn poll_for_peer(
    signaling: &dyn SignalingService,
    room: &str,
    my_hash: &str,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> io::Result<String> {
    let deadline = citadel_io::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    loop {
        if citadel_io::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for peer",
            ));
        }

        let participants = signaling.list_children(room, "participants").await?;
        if participants.len() >= 2 {
            // Find the other participant's hash.
            for (_, value) in &participants {
                if let Ok(hello) = serde_json::from_value::<HelloMessage>(value.clone()) {
                    if hello.identity_hash != my_hash {
                        return Ok(hello.identity_hash);
                    }
                }
            }
        }

        citadel_io::tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
    }
}

/// Server (Alpha) flow: create offer, publish, wait for answer.
async fn alpha_flow(
    signaling: &dyn SignalingService,
    room: &str,
    ice_servers: &[IceServerConfig],
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> io::Result<WasmStream> {
    let pc = create_peer_connection(ice_servers)?;
    let dc = create_reliable_data_channel(&pc, "citadel-serverless");

    // Create and publish offer.
    let (sdp, candidates) = create_offer_with_candidates(&pc).await?;
    let exchange = SdpExchange {
        sdp,
        ice_candidates: candidates,
    };
    let offer_value = serde_json::to_value(&exchange)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    signaling.publish(room, "offer", offer_value).await?;

    // Poll for answer.
    let answer =
        poll_for_key::<SdpExchange>(signaling, room, "answer", poll_interval_ms, timeout_ms)
            .await?;

    apply_answer(&pc, &answer.sdp, &answer.ice_candidates).await?;
    wait_for_datachannel_open(&dc).await?;

    let pc_arc = Arc::new(pc);
    Ok(WasmStream::DataChannel(WasmDataChannelStream::new(
        dc, pc_arc,
    )))
}

/// Client (Beta) flow: wait for offer, create answer, publish.
async fn beta_flow(
    signaling: &dyn SignalingService,
    room: &str,
    ice_servers: &[IceServerConfig],
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> io::Result<WasmStream> {
    // Poll for offer.
    let offer =
        poll_for_key::<SdpExchange>(signaling, room, "offer", poll_interval_ms, timeout_ms).await?;

    let pc = create_peer_connection(ice_servers)?;
    let (answer_sdp, answer_candidates) =
        accept_offer_with_candidates(&pc, &offer.sdp, &offer.ice_candidates).await?;

    // Publish answer.
    let exchange = SdpExchange {
        sdp: answer_sdp,
        ice_candidates: answer_candidates,
    };
    let answer_value = serde_json::to_value(&exchange)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    signaling.publish(room, "answer", answer_value).await?;

    // Wait for the remote DataChannel.
    let dc = wait_for_remote_datachannel(&pc).await?;
    wait_for_datachannel_open(&dc).await?;

    let pc_arc = Arc::new(pc);
    Ok(WasmStream::DataChannel(WasmDataChannelStream::new(
        dc, pc_arc,
    )))
}

/// Poll the signaling service for a key, deserializing the value.
async fn poll_for_key<T: serde::de::DeserializeOwned>(
    signaling: &dyn SignalingService,
    room: &str,
    key: &str,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> io::Result<T> {
    let deadline = citadel_io::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    loop {
        if citadel_io::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for signaling key: {key}"),
            ));
        }

        if let Some(value) = signaling.read(room, key).await? {
            let result: T = serde_json::from_value(value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            return Ok(result);
        }

        citadel_io::tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
    }
}
