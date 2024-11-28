//! # Basic Citadel Server Example
//!
//! This example demonstrates how to create a basic Citadel server that facilitates
//! peer-to-peer and group connections. This is the simplest form of a Citadel server,
//! which acts primarily as a connection broker.
//!
//! ## Features Demonstrated
//! - Basic server setup
//! - Connection brokering for P2P and group connections
//! - Server configuration using environment variables
//! - Use of the EmptyKernel for simple connection handling
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! cargo run --example server_basic
//! ```
//!
//! ## Note
//! This server only facilitates connections between peers. It does not handle direct
//! client-server communication. For bidirectional client-server communication,
//! see the `server_echo.rs` example which uses a `ClientConnectListenerKernel`.

use citadel_sdk::prefabs::server;
use citadel_sdk::prelude::*;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    println!("Starting server on {}", server_addr);

    // This is a basic server. It will only help facilitate p2p and group connections.
    // Clients will not be able to communicate directly with this server through channels.
    // If post-connection client-server bidirectional communication is needed, use a
    // `ClientConnectListenerKernel` instead which runs a closure each time a new connection is
    // established with a client
    let kernel = server::empty::EmptyKernel;

    // Build the server
    let node = NodeBuilder::default()
        .with_node_type(NodeType::server(server_addr)?)
        .build(kernel)?;

    // Run the server
    node.await?;

    Ok(())
}
