//! # Echo Server Example
//!
//! This example demonstrates how to create a Citadel server that actively
//! communicates with clients. Unlike the basic server examples, this server
//! uses a `ClientConnectListenerKernel` to handle bidirectional communication
//! with connected clients.
//!
//! ## Features Demonstrated
//! - Active client-server communication
//! - ClientConnectListenerKernel usage
//! - Channel-based message handling
//! - Connection event handling
//! - Asynchronous message processing
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! cargo run --example server_echo
//! ```
//!
//! Then run the corresponding client:
//! ```bash
//! cargo run --example client_echo
//! ```
//!
//! ## How it Works
//! 1. Server starts and listens for connections
//! 2. For each new client connection:
//!    - Creates a new message channel
//!    - Listens for incoming messages
//!    - Echoes received messages back to the client
//! 3. Handles multiple clients concurrently
//!
//! ## Note
//! This server demonstrates active client-server communication using
//! the `ClientConnectListenerKernel`. It processes each message and
//! sends it back to the client, making it ideal for testing client
//! connectivity and message handling.

use citadel_sdk::{
    prefabs::server::client_connect_listener::ClientConnectListenerKernel, prelude::*,
};
use futures::StreamExt;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    println!("Starting server on {}", server_addr);

    // Set up the server kernel. The provided closure will be called every time a new client connects
    let kernel = ClientConnectListenerKernel::new(move |conn| async move {
        let cid = conn.cid;
        println!("New client connected! CID: {cid}");

        let (mut tx, mut rx) = conn.split();
        while let Some(msg) = rx.next().await {
            println!(
                "Received message from client {cid}: {}",
                String::from_utf8_lossy(msg.as_ref())
            );

            // Echo the message back
            if let Err(e) = tx.send(msg).await {
                println!("Error sending response: {}", e);
            }
        }

        Ok(())
    });

    // Build the server
    let node = DefaultNodeBuilder::default()
        .with_node_type(NodeType::server(server_addr)?)
        .build(kernel)?;

    // Run the server
    node.await?;

    Ok(())
}
