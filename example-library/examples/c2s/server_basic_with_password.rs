//! # Password-Protected Citadel Server Example
//!
//! This example demonstrates how to create a Citadel server that requires password
//! authentication from clients. It provides an additional layer of security by
//! requiring clients to provide a valid password before establishing a connection.
//!
//! ## Features Demonstrated
//! - Server password protection
//! - Basic connection brokering
//! - Server configuration with environment variables
//! - Secure password handling
//! - Use of EmptyKernel for connection handling
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! export CITADEL_SERVER_PASSWORD="your_secure_password"
//! cargo run --example server_basic_with_password
//! ```
//!
//! ## Security Notes
//! - Never hardcode passwords in production code
//! - Avoid storing passwords in environment variables in production
//! - Use secure password management systems for production deployments
//! - Server password protects initial connection, different from user accounts
//!
//! ## How it Works
//! 1. Server starts with password protection enabled
//! 2. Clients must provide correct password to connect
//! 3. After authentication, server acts as connection broker
//! 4. Facilitates P2P and group connections between authenticated clients
//!
//! ## Note
//! This server only facilitates connections between peers. It does not handle
//! direct client-server communication. For bidirectional client-server
//! communication, use a `ClientConnectListenerKernel` instead.

use citadel_sdk::prefabs::server;
use citadel_sdk::prelude::*;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    // Security note: Do not hardcode password in production into the environment. It exposes your application
    // to local attacks resultant from rogue processes or users that scan the env for secrets.
    let connect_password =
        env::var("CITADEL_SERVER_PASSWORD").expect("CITADEL_SERVER_PASSWORD not set");
    println!("Starting server on {}", server_addr);

    // This is a basic server. It will only help facilitate p2p and group connections.
    // Clients will not be able to communicate directly with this server through channels.
    // If post-connection client-server bidirectional communication is needed, use a
    // `ClientConnectListenerKernel` instead which runs each time a new connection is
    // established with a client
    let kernel = server::empty::EmptyKernel;

    // Build the server. It is password-protected, meaning that each time
    // a client attempts to register or connect, they must provide the password.
    // This "password" is effectively a pre-shared key (PSK)
    let node = DefaultNodeBuilder::default()
        .with_node_type(NodeType::server(server_addr)?)
        .with_server_password(connect_password)
        .build(kernel)?;

    // Run the server
    node.await?;

    Ok(())
}
