//! # Echo Client Example with Persistent Account
//!
//! This example demonstrates how to create a client that establishes a persistent,
//! credentialed connection with a Citadel server and exchanges messages. Unlike the
//! transient connection example, this client creates a persistent account that can
//! be reused across sessions.
//!
//! ## Features Demonstrated
//! - Credentialed registration with persistent account
//! - Perfect Forward Secrecy mode for enhanced security
//! - Bidirectional message exchange with server
//! - Channel-based communication
//! - Error handling and connection management
//!
//! ## Prerequisites
//! - A running Citadel server (use `server_echo.rs` for full functionality)
//! - Server must be configured to accept credentialed connections
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! cargo run --example client_echo
//! ```
//!
//! ## How it Works
//! 1. Establishes a credentialed connection with username/password
//! 2. Creates a secure channel with the server
//! 3. Sends a message and waits for the server's echo response
//! 4. Demonstrates proper connection cleanup on exit

use citadel_sdk::{
    prefabs::client::single_connection::SingleClientServerConnectionKernel, prelude::*,
};
use futures::StreamExt;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    println!("Connecting to server at {}", server_addr);

    // Set up session security
    let session_security = SessionSecuritySettingsBuilder::default()
        .with_secrecy_mode(SecrecyMode::Perfect)
        .with_crypto_params(KemAlgorithm::Kyber + EncryptionAlgorithm::AES_GCM_256)
        .build()?;

    // Create server connection settings
    let server_connection_settings =
        DefaultServerConnectionSettingsBuilder::credentialed_registration(
            server_addr,
            "my_username",
            "My Name",
            "notsecurepassword",
        )
        .with_session_security_settings(session_security)
        .disable_udp()
        .build()?;

    // Create client kernel
    let kernel = SingleClientServerConnectionKernel::new(
        server_connection_settings,
        |connect_success, remote| async move {
            println!("Connected to server! CID: {}", connect_success.cid);
            let (tx, mut rx) = connect_success.channel.split();

            let message = "Hello from client!";
            // Send initial message
            let msg = SecBuffer::from(message);
            if let Err(e) = tx.send_message(msg).await {
                println!("Error sending message: {}", e);
                return Err(e);
            }

            // Receive messages using Stream trait
            if let Some(echo) = rx.next().await {
                let response = String::from_utf8(echo.as_ref().to_vec())
                    .expect("Failed to convert message to string");
                println!("Received echo from server: {response}",);
                assert_eq!(&response, message);
            } else {
                println!("No message received from server");
                return Err(NetworkError::msg("No message received from server"));
            }

            remote.shutdown_kernel().await
        },
    );

    // Build the node
    let client = DefaultNodeBuilder::default().build(kernel)?;

    // Run the node
    client.await?;

    Ok(())
}
