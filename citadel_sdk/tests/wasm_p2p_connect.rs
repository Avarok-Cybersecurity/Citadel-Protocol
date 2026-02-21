//! WASM P2P integration test — two WASM clients connect through a native server.
//!
//! Requires a running `wasm_test_server` on `ws://127.0.0.1:25522`.
//! Run via: `cargo make test-wasm-p2p-docker` (Docker) or manually start the server.
//!
//! Uses `wasm-pack test --headless --chrome` to execute in a real browser
//! environment with native WebSocket support. Both clients run concurrently
//! in a single-threaded WASM runtime via `futures::join!`.
#![cfg(target_family = "wasm")]

use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use uuid::Uuid;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const WS_SERVER: &str = "127.0.0.1:25522";

/// Two WASM clients connect to the native server, then P2P connect through it.
#[wasm_bindgen_test]
async fn test_wasm_p2p_connect() {
    citadel_logging::setup_log();

    let uuid_a = Uuid::new_v4();
    let uuid_b = Uuid::new_v4();

    // Client A: connect to server, then P2P to B
    let agg_a = PeerConnectionSetupAggregator::default()
        .with_peer_custom(uuid_b)
        .with_udp_mode(UdpMode::Disabled)
        .ensure_registered()
        .add();

    let settings_a = DefaultServerConnectionSettingsBuilder::transient_with_id(WS_SERVER, uuid_a)
        .with_udp_mode(UdpMode::Disabled)
        .build()
        .expect("build settings A");

    let kernel_a =
        PeerConnectionKernel::new(settings_a, agg_a, |mut connections, remote| async move {
            log::info!("Client A connected to server, awaiting P2P...");
            let conn = connections.recv().await.unwrap()?;
            log::info!(
                "Client A: P2P connected to peer cid={}",
                conn.channel.get_peer_cid()
            );
            remote.shutdown_kernel().await
        });

    let client_a = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .build(kernel_a)
        .expect("build client A");

    // Client B: connect to server, then P2P to A
    let agg_b = PeerConnectionSetupAggregator::default()
        .with_peer_custom(uuid_a)
        .with_udp_mode(UdpMode::Disabled)
        .ensure_registered()
        .add();

    let settings_b = DefaultServerConnectionSettingsBuilder::transient_with_id(WS_SERVER, uuid_b)
        .with_udp_mode(UdpMode::Disabled)
        .build()
        .expect("build settings B");

    let kernel_b =
        PeerConnectionKernel::new(settings_b, agg_b, |mut connections, remote| async move {
            log::info!("Client B connected to server, awaiting P2P...");
            let conn = connections.recv().await.unwrap()?;
            log::info!(
                "Client B: P2P connected to peer cid={}",
                conn.channel.get_peer_cid()
            );
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
