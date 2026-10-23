//! Minimal WebSocket server for WASM integration testing.
//!
//! Starts a Citadel server that accepts WebSocket connections on port 25522.
//! Used by `cargo make test-wasm-integration` to provide a native backend
//! for WASM client tests running in headless Chrome.
//!
//! It also answers STUN binding requests on [`BROWSER_STUN_SERVERS`]: a browser's ICE agent
//! contacts its node's STUN servers, and one that never answers holds ICE gathering for the
//! agent's whole STUN timeout (about 40 s a side), past the browser test's deadline.
//!
//! # Usage
//! ```sh
//! cargo run --example wasm_test_server --features localhost-testing
//! ```

use citadel_io::tokio;
use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::BROWSER_STUN_SERVERS;
use std::net::SocketAddr;

const WS_PORT: u16 = 25522;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    citadel_logging::setup_log();

    for endpoint in BROWSER_STUN_SERVERS {
        let socket = tokio::net::UdpSocket::bind(endpoint).await?;
        drop(tokio::spawn(answer_stun(socket)));
    }

    let tcp_addr: SocketAddr = "127.0.0.1:25521".parse()?;
    let ws_addr: SocketAddr = format!("127.0.0.1:{WS_PORT}").parse()?;

    let kernel = ClientConnectListenerKernel::<_, _, StackedRatchet>::new(|conn| async move {
        log::info!("WASM client connected: cid={}", conn.cid);
        Ok(())
    });

    let server = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Server(tcp_addr))
        .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
        .with_path_policy(citadel_sdk::test_common::localhost_path_policy())
        .with_websocket_listener(ws_addr)
        .build(kernel)?;

    eprintln!("WASM test server listening on ws://127.0.0.1:{WS_PORT}");
    println!("{{\"ws_addr\": \"127.0.0.1:{WS_PORT}\"}}");

    server.await?;
    Ok(())
}

/// Answers every STUN binding request with the sender's address (RFC 5389 §7.3).
async fn answer_stun(socket: tokio::net::UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        if let Some(response) = binding_success(&buf[..len], from) {
            let _ = socket.send_to(&response, from).await;
        }
    }
}

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// The binding success response to `request`, carrying `from` as its XOR-MAPPED-ADDRESS, or
/// `None` when `request` is not a STUN binding request.
fn binding_success(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let header = request.get(..20)?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let cookie = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if kind != BINDING_REQUEST || cookie != MAGIC_COOKIE {
        return None;
    }
    let transaction_id = &header[8..20];
    let SocketAddr::V4(from) = from else {
        return None;
    };
    let port = from.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let address = u32::from(*from.ip()) ^ MAGIC_COOKIE;
    let mut value = vec![0u8, 0x01];
    value.extend_from_slice(&port.to_be_bytes());
    value.extend_from_slice(&address.to_be_bytes());

    let mut response = Vec::with_capacity(32);
    response.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    response.extend_from_slice(&(4 + value.len() as u16).to_be_bytes());
    response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(transaction_id);
    response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&(value.len() as u16).to_be_bytes());
    response.extend_from_slice(&value);
    Some(response)
}
