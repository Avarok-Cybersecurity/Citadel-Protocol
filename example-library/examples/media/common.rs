//! Shared plumbing for the media examples, included via `#[path = "common.rs"] mod common;`.
#![allow(dead_code)] // shared by four example binaries; each uses a subset

use citadel_sdk::media::*;
use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
use citadel_sdk::prelude::*;
use std::{error::Error, future::Future, path::PathBuf, time::Duration};

/// Public fixtures these examples were written against (WAV: 3 s PCM; IVF: VP8 352x288).
pub const WAV_FIXTURE_URL: &str = "https://download.samplelib.com/wav/sample-3s.wav";
pub const IVF_FIXTURE_URL: &str =
    "https://storage.googleapis.com/downloads.webmproject.org/test_data/libvpx/vp80-05-sharpness-1428.ivf";

/// The media file a sender streams. Required — examples never download.
pub fn media_input(fixture_url: &str) -> PathBuf {
    let hint = format!("media file to stream; download e.g. {fixture_url}");
    let path = PathBuf::from(require("CITADEL_MEDIA_FILE", &hint));
    if path.is_file() {
        return path;
    }
    let p = path.display();
    eprintln!("CITADEL_MEDIA_FILE={p} is not a readable file; {hint}");
    std::process::exit(1)
}

/// `CITADEL_MEDIA_OUT`, defaulting to `./media_out.<ext>` (CLI convenience; always printed).
pub fn media_output(ext: &str) -> PathBuf {
    let path = std::env::var("CITADEL_MEDIA_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("./media_out.{ext}")));
    println!("Received media will be written to {}", path.display());
    path
}

fn require(key: &str, what: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("environment variable {key} is not set; expected: {what}");
        std::process::exit(1);
    })
}

pub fn net_err(err: impl std::fmt::Display) -> NetworkError {
    NetworkError::msg(err.to_string())
}

/// One explicit, validated transport config shared by all four examples.
pub fn transport_config() -> MediaTransportConfig {
    let cfg = MediaTransportConfig {
        media: citadel_media::MediaConfig {
            max_fragment_payload: RECOMMENDED_FRAGMENT_PAYLOAD,
            max_frame_bytes: 1 << 20, // bounds one logical frame (and the IVF reader's allocation)
            max_reorder_window: 64,   // frames arriving >64 sequence numbers behind are TooOld
            jitter_depth_micros: 60_000, // 60 ms: three 20 ms audio frames of reorder absorption
            max_pending_frames: 64,   // partially reassembled frames held at once (DoS bound)
        },
        send_queue_frames: 256, // ~5 s of 20 ms audio frames before the drop policy engages
        udp_payload_budget: RECOMMENDED_UDP_PAYLOAD_BUDGET,
        udp_wait: Duration::from_secs(3), // then fall back to the ordered-reliable channel
    };
    cfg.validate().expect("example media config is valid");
    cfg
}

/// Reads the connection env vars (failing fast), connects with UDP enabled on
/// both the C2S and P2P links, runs `on_peer`, then shuts the kernel down.
pub async fn run_media_peer<F, Fut>(on_peer: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce(results::PeerConnectSuccess<StackedRatchet>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), NetworkError>> + Send + 'static,
{
    let server_addr = require("CITADEL_SERVER_ADDR", "server addr, e.g. 127.0.0.1:25021");
    let my_user = require("CITADEL_MY_USER", "username for this peer");
    let other_user = require("CITADEL_OTHER_USER", "peer username to stream with");
    // BestEffort secrecy: per-message rekeying would throttle the control lane.
    let session_security = SessionSecuritySettingsBuilder::default()
        .with_secrecy_mode(SecrecyMode::BestEffort)
        .with_crypto_params(KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256)
        .build()?;
    let server_settings = DefaultServerConnectionSettingsBuilder::credentialed_registration(
        server_addr,
        my_user,
        "Media Example",
        "notsecurepassword",
    )
    .with_session_security_settings(session_security)
    .with_udp_mode(UdpMode::Enabled)
    .build()?;
    let peer = PeerConnectionSetupAggregator::default()
        .with_peer_custom(other_user)
        .with_session_security_settings(session_security)
        .with_udp_mode(UdpMode::Enabled)
        .ensure_registered() // make startup order-independent
        .add();
    let kernel =
        PeerConnectionKernel::new(server_settings, peer, move |mut conns, remote| async move {
            let closed = || NetworkError::msg("peer connection stream closed");
            let conn = conns.recv().await.ok_or_else(closed)??;
            println!("Connected to peer {:?}", conn.remote.target_username());
            on_peer(conn).await?;
            remote.shutdown_kernel().await
        });
    DefaultNodeBuilder::default().build(kernel)?.await?;
    Ok(())
}

/// One-line receiver progress report (frames, gaps, jitter counters).
pub fn print_receiver_stats(rx: &MediaReceiver) {
    let s = rx.stats();
    println!(
        "[stats] delivered {} | gaps {} | late {} | too-old {} | dup {}",
        s.frames_delivered, s.gaps_skipped, s.frames_late, s.frames_too_old, s.fragments_duplicate
    );
}
