//! # Password-Protected Server Connection Example
//!
//! This example demonstrates how to connect to a Citadel server that requires
//! a password for authentication. It shows proper password handling and secure
//! connection establishment.
//!
//! ## Features Demonstrated
//! - Server password authentication
//! - Perfect Forward Secrecy mode
//! - Secure password handling
//! - Connection establishment with protected server
//! - Error handling for authentication failures
//!
//! ## Prerequisites
//! - A running Citadel server with password protection enabled
//!   (use `server_basic_with_password.rs`)
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25000"
//! export CITADEL_SERVER_PASSWORD="your_secure_password"
//! cargo run --example client_basic_with_server_password
//! ```
//!
//! ## Security Notes
//! - Never hardcode passwords in production code
//! - Avoid storing passwords in environment variables in production
//! - Use secure password management systems for production deployments
//! - The server password is different from user account credentials
//!
//! ## How it Works
//! 1. Client reads server password from environment
//! 2. Establishes encrypted connection to server
//! 3. Performs password-based authentication
//! 4. Maintains secure session after authentication

use citadel_sdk::{
    prefabs::client::single_connection::SingleClientServerConnectionKernel, prelude::*,
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    // Security note: Do not hardcode password in production into the environment. It exposes your application
    // to local attacks resultant from rogue processes or users that scan the env for secrets.
    let connect_password =
        env::var("CITADEL_SERVER_PASSWORD").expect("CITADEL_SERVER_PASSWORD not set");
    println!("Connecting to server at {server_addr}");

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
        .with_session_password(connect_password)
        .disable_udp()
        .build()?;

    // Create client kernel
    let kernel =
        SingleClientServerConnectionKernel::new(server_connection_settings, |conn| async move {
            println!("Connected to server! CID: {}", conn.cid);
            conn.shutdown_kernel().await
        });

    // Build the node
    let client = DefaultNodeBuilder::default().build(kernel)?;

    // Run the node
    client.await?;

    Ok(())
}
