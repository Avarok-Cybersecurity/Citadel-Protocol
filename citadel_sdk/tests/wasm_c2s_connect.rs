//! WASM C2S integration test — connects a WASM client to a native server.
//!
//! Requires a running `wasm_test_server` on `ws://127.0.0.1:25522`.
//! Run via: `cargo make test-wasm-integration`
//!
//! Uses `wasm-pack test --headless --chrome` to execute in a real browser
//! environment with native WebSocket support.
#![cfg(target_family = "wasm")]

use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const WS_SERVER: &str = "127.0.0.1:25522";

/// Connect to the native server with transient credentials, then disconnect.
#[wasm_bindgen_test]
async fn test_c2s_transient_connect() {
    citadel_logging::setup_log();

    let settings = DefaultServerConnectionSettingsBuilder::transient(WS_SERVER)
        .with_udp_mode(UdpMode::Disabled)
        .build()
        .expect("build settings");

    let kernel = SingleClientServerConnectionKernel::new(settings, |conn| async move {
        log::info!("Connected to server! cid={}", conn.cid);
        conn.remote.shutdown_kernel().await
    });

    let client = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .build(kernel)
        .expect("build client");

    client.await.expect("client run");
}
