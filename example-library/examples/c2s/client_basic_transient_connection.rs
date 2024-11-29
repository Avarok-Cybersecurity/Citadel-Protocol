//! # Basic Transient Connection Example
//!
//! This example demonstrates how to create a temporary, non-persistent connection
//! to a Citadel server. A transient connection exists only for the duration of
//! the session and does not maintain any state between connections.
//!
//! ## Features Demonstrated
//! - Transient (temporary) connections
//! - Basic client-server communication
//! - Session-only state management
//! - Connection cleanup handling
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! cargo run --example client_basic_transient_connection
//! ```
//!
//! ## How it Works
//! 1. Client establishes temporary connection to server
//! 2. No persistent account or credentials are created
//! 3. Connection remains active for the session duration
//! 4. All state is cleared when connection closes
//!
//! ## Use Cases
//! Transient connections are ideal for:
//! - Temporary or one-time connections
//! - Applications without need for persistence
//! - Testing and development
//! - Scenarios where state persistence isn't required
//!
//! ## Security Note
//! While transient connections don't maintain persistent identity, the server
//! can still enforce security through client certificates at the transport
//! layer to ensure only authorized clients can connect.

use citadel_sdk::{
    prefabs::client::single_connection::SingleClientServerConnectionKernel, prelude::*,
};
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

    // Create server connection settings. If a custom transient ID is required, use `transient_with_id` over `transient`.
    let server_connection_settings = ServerConnectionSettingsBuilder::transient(server_addr)
        .with_session_security_settings(session_security)
        .disable_udp()
        .build()?;

    // Create client kernel
    let kernel = SingleClientServerConnectionKernel::new(
        server_connection_settings,
        |connect_success, remote| async move {
            println!("Connected to server! CID: {}", connect_success.cid);
            remote.shutdown_kernel().await
        },
    );

    // Build the node
    let client = NodeBuilder::default().build(kernel)?;

    // Run the node
    client.await?;

    Ok(())
}
