//! # P2P Chat Example
//!
//! This example demonstrates how to implement a peer-to-peer chat application using the Citadel Protocol.
//! It shows how to:
//! - Set up secure P2P connections between two peers
//! - Handle real-time message exchange
//! - Use the Perfect Forward Secrecy mode for enhanced security
//! - Implement interactive input/output for chat functionality
//!
//! ## Usage
//!
//! Run two instances with different user identities:
//! ```bash
//! # First peer
//! export CITADEL_MY_USER="user1"
//! export CITADEL_OTHER_USER="user2"
//! cargo run --example chat
//!
//! # Second peer (in another terminal)
//! export CITADEL_MY_USER="user2"
//! export CITADEL_OTHER_USER="user1"
//! cargo run --example chat
//! ```
//!
//! ## Features Demonstrated
//! - Secure P2P connection establishment
//! - Perfect Forward Secrecy mode
//! - Async message handling
//! - Interactive terminal I/O
//! - Error handling and connection management

use citadel_sdk::{
    prefabs::client::peer_connection::{PeerConnectionKernel, PeerConnectionSetupAggregator},
    prelude::*,
};
use futures::StreamExt;
use std::env;
use tokio::io::AsyncBufReadExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    let my_user = env::var("CITADEL_MY_USER").expect("MY_USER not set");
    let other_user = env::var("CITADEL_OTHER_USER").expect("OTHER_USER not set");

    println!("Starting P2P chat as peer {my_user}");
    println!("Will connect to peer {other_user}");

    // Set up session security
    let session_security = SessionSecuritySettingsBuilder::default()
        .with_secrecy_mode(SecrecyMode::Perfect)
        .with_crypto_params(KemAlgorithm::Kyber + EncryptionAlgorithm::AES_GCM_256)
        .build()?;

    // Create server connection settings
    let server_connection_settings = ServerConnectionSettingsBuilder::credentialed_registration(
        server_addr,
        my_user,
        "Name",
        "notsecurepassword",
    )
    .with_session_security_settings(session_security)
    .disable_udp()
    .build()?;

    // Create peer connection setup
    let peer_connection = PeerConnectionSetupAggregator::default()
        .with_peer_custom(other_user)
        .with_session_security_settings(session_security)
        .enable_udp()
        .add();

    // Set up the peer connection kernel
    let kernel = PeerConnectionKernel::new(
        server_connection_settings,
        peer_connection,
        move |mut connection, remote| async move {
            println!("Connected to server successfully!");

            // Wait for peer connection
            let peer_conn = connection.recv().await.unwrap()?;
            println!(
                "Connected to peer {:?}!",
                peer_conn.remote.target_username()
            );

            // Set up message handling
            let (tx, mut message_stream) = peer_conn.channel.split();
            let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

            println!("Type your messages (press Enter to send, Ctrl+C to quit):");

            loop {
                tokio::select! {
                    msg = message_stream.next() => {
                        if let Some(msg) = msg {
                            println!("\rReceived: {}", String::from_utf8_lossy(msg.as_ref()));
                        }
                    }
                    line = stdin.next_line() => {
                        match line {
                            Ok(Some(msg)) if !msg.is_empty() => {
                                tx.send_message(msg.into_bytes().into()).await?;
                            }
                            Ok(None) => break, // EOF
                            _ => continue,
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        println!("\nReceived Ctrl+C, shutting down...");
                        break;
                    }
                }
            }

            remote.shutdown_kernel().await
        },
    );

    // Build the peer
    let node = NodeBuilder::default().build(kernel)?;

    // Run the peer
    node.await?;

    Ok(())
}
