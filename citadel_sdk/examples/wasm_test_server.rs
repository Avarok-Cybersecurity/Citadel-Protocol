//! Minimal WebSocket server for WASM integration testing.
//!
//! Starts a Citadel server that accepts WebSocket connections on port 25522.
//! Used by `cargo make test-wasm-integration` to provide a native backend
//! for WASM client tests running in headless Chrome.
//!
//! # Usage
//! ```sh
//! cargo run --example wasm_test_server --features localhost-testing
//! ```

use citadel_io::tokio;
use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
use citadel_sdk::prelude::*;

const WS_PORT: u16 = 25522;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    citadel_logging::setup_log();

    let tcp_addr: std::net::SocketAddr = "127.0.0.1:25521".parse()?;
    let ws_addr: std::net::SocketAddr = format!("127.0.0.1:{WS_PORT}").parse()?;

    let kernel = ClientConnectListenerKernel::<_, _, StackedRatchet>::new(|conn| async move {
        log::info!("WASM client connected: cid={}", conn.cid);
        Ok(())
    });

    let server = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Server(tcp_addr))
        .with_websocket_listener(ws_addr)
        .build(kernel)?;

    eprintln!("WASM test server listening on ws://127.0.0.1:{WS_PORT}");
    println!("{{\"ws_addr\": \"127.0.0.1:{WS_PORT}\"}}");

    server.await?;
    Ok(())
}
