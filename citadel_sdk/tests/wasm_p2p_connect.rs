//! WASM P2P integration test — two WASM clients connect through a native server, P2P-connect over
//! a WebRTC DataChannel pair, then exercise the UDP subsystem (unordered DataChannel) end-to-end:
//! a raw datagram echo plus a `citadel_sdk::media` stream.
//!
//! Requires a running `wasm_test_server` on `ws://127.0.0.1:25522`.
//! Run via: `cargo make test-wasm-p2p-docker` (Docker) or manually start the server.
//!
//! Uses `wasm-pack test --headless --chrome` to execute in a real browser
//! environment with native WebSocket support. Both clients run concurrently
//! in a single-threaded WASM runtime via `futures::join!`.
#![cfg(target_family = "wasm")]

use bytes::Bytes;
use citadel_sdk::citadel_media::config::MediaConfig;
use citadel_sdk::citadel_media::descriptor::MediaTrackDescriptor;
use citadel_sdk::citadel_media::frame::{FrameFlags, TrackId, TrackKind};
use citadel_sdk::media::{
    MediaEndpoint, MediaEvent, MediaTransportConfig, MediaTransportKind,
    RECOMMENDED_FRAGMENT_PAYLOAD, RECOMMENDED_UDP_PAYLOAD_BUDGET,
};
use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use futures::StreamExt;
use uuid::Uuid;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const WS_SERVER: &str = "127.0.0.1:25522";
const MEDIA_FRAMES: usize = 50;
/// 20 ms of synthetic 48 kHz stereo PCM16 — large enough to fragment at the recommended budget.
const PCM_FRAME_BYTES: usize = 3840;

fn media_config() -> MediaTransportConfig {
    let cfg = MediaTransportConfig {
        media: MediaConfig {
            max_fragment_payload: RECOMMENDED_FRAGMENT_PAYLOAD,
            max_frame_bytes: 64 * 1024,
            max_reorder_window: 1024,
            jitter_depth_micros: 500_000,
            max_pending_frames: 256,
        },
        send_queue_frames: 256,
        udp_payload_budget: RECOMMENDED_UDP_PAYLOAD_BUDGET,
        udp_wait: std::time::Duration::from_secs(10),
    };
    cfg.validate().expect("valid media config");
    cfg
}

fn pcm_frame(index: usize) -> Bytes {
    Bytes::from(
        (0..PCM_FRAME_BYTES)
            .map(|i| ((i + index) & 0xFF) as u8)
            .collect::<Vec<u8>>(),
    )
}

/// Two WASM clients connect to the native server, then P2P connect through it. With UDP enabled,
/// each side must also receive a real `UdpChannel` over the unordered DataChannel; A echoes what
/// B sends, then B streams synthetic PCM frames to A via `citadel_sdk::media`.
#[wasm_bindgen_test]
async fn test_wasm_p2p_connect() {
    // Surface the panic text in the harness (wasm-bindgen-test captures console.error);
    // citadel_logging's default hook exits before the message reaches the console.
    std::panic::set_hook(Box::new(|info| {
        web_sys::console::error_1(&format!("TEST PANIC: {info}").into());
    }));
    citadel_logging::setup_log_no_panic_hook();

    let uuid_a = Uuid::new_v4();
    let uuid_b = Uuid::new_v4();

    // Client A: connect to server, then P2P to B
    let agg_a = PeerConnectionSetupAggregator::default()
        .with_peer_custom(uuid_b)
        .with_udp_mode(UdpMode::Enabled)
        .ensure_registered()
        .add();

    let settings_a = DefaultServerConnectionSettingsBuilder::transient_with_id(WS_SERVER, uuid_a)
        .with_udp_mode(UdpMode::Disabled)
        .build()
        .expect("build settings A");

    let kernel_a =
        PeerConnectionKernel::new(settings_a, agg_a, |mut connections, remote| async move {
            web_sys::console::log_1(&"A: connected".into());
            let mut conn = connections.recv().await.unwrap()?;
            log::info!(
                "Client A: P2P connected to peer cid={}",
                conn.channel.get_peer_cid()
            );
            web_sys::console::log_1(&"A: p2p connected, awaiting udp channel".into());
            // Raw UDP echo: prove the unordered DataChannel feeds a real UdpChannel.
            let chan = conn
                .udp_channel_rx
                .take()
                .expect("udp rx present")
                .await
                .expect("udp channel delivered");
            web_sys::console::log_1(&"A: udp channel up".into());
            let (tx, mut rx) = chan.split();
            let msg = rx.next().await.expect("udp datagram");
            tx.unbounded_send(msg.as_ref()).expect("echo send");

            // Media receive: collect the full synthetic PCM stream.
            let endpoint = MediaEndpoint::from_channels(conn.channel, None, media_config()).await?;
            assert_eq!(endpoint.kind(), MediaTransportKind::Reliable);
            let (_media_tx, mut media_rx) = endpoint.split();
            let mut frames = Vec::new();
            loop {
                match media_rx.next_event().await {
                    MediaEvent::Tracks(_) => {}
                    MediaEvent::Frame(frame) => frames.push(frame),
                    MediaEvent::Gap {
                        missing_from,
                        missing_to,
                        ..
                    } => {
                        panic!("media loss {missing_from}..={missing_to}")
                    }
                    MediaEvent::EndOfStream(_) => break,
                    MediaEvent::Closed => panic!("media closed early"),
                }
            }
            assert_eq!(frames.len(), MEDIA_FRAMES);
            for (i, frame) in frames.iter().enumerate() {
                assert_eq!(frame.payload, pcm_frame(i), "frame {i} byte-exact");
            }
            drop((tx, rx));
            remote.shutdown_kernel().await
        });

    let client_a = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .build(kernel_a)
        .expect("build client A");

    // Client B: connect to server, then P2P to A
    let agg_b = PeerConnectionSetupAggregator::default()
        .with_peer_custom(uuid_a)
        .with_udp_mode(UdpMode::Enabled)
        .ensure_registered()
        .add();

    let settings_b = DefaultServerConnectionSettingsBuilder::transient_with_id(WS_SERVER, uuid_b)
        .with_udp_mode(UdpMode::Disabled)
        .build()
        .expect("build settings B");

    let kernel_b =
        PeerConnectionKernel::new(settings_b, agg_b, |mut connections, remote| async move {
            web_sys::console::log_1(&"B: connected".into());
            let mut conn = connections.recv().await.unwrap()?;
            log::info!(
                "Client B: P2P connected to peer cid={}",
                conn.channel.get_peer_cid()
            );
            let chan = conn
                .udp_channel_rx
                .take()
                .expect("udp rx present")
                .await
                .expect("udp channel delivered");
            let (tx, mut rx) = chan.split();
            tx.unbounded_send(b"udp over webrtc" as &[u8])
                .expect("send");
            assert_eq!(rx.next().await.expect("echo").as_ref(), b"udp over webrtc");

            // Media send: stream synthetic PCM frames, then EOS.
            let endpoint = MediaEndpoint::from_channels(conn.channel, None, media_config()).await?;
            let (mut media_tx, _media_rx) = endpoint.split();
            media_tx
                .announce(&[MediaTrackDescriptor {
                    track: TrackId(0),
                    kind: TrackKind::Audio,
                    clock_rate: 48_000,
                    codec: *b"PCM\0",
                    channels: 2,
                    width: 0,
                    height: 0,
                    name: "audio".into(),
                }])
                .await?;
            for i in 0..MEDIA_FRAMES {
                let dropped = media_tx
                    .send_frame(
                        TrackId(0),
                        TrackKind::Audio,
                        (i * 960) as u32,
                        FrameFlags::KEYFRAME,
                        pcm_frame(i),
                    )
                    .expect("send frame");
                assert_eq!(dropped, 0);
            }
            media_tx.end_of_stream(TrackId(0)).await?;
            // Give A time to drain before teardown.
            citadel_io::time::sleep(std::time::Duration::from_millis(1500)).await;
            drop((tx, rx));
            remote.shutdown_kernel().await
        });

    let client_b = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .build(kernel_b)
        .expect("build client B");

    // Run both clients concurrently in the single-threaded WASM runtime
    let (result_a, result_b) = futures::join!(client_a, client_b);
    result_a.expect("Client A failed");
    result_b.expect("Client B failed");
}
