//! # P2P File Transfer Example
//!
//! This example demonstrates how to set up a peer connection between two peers and transfer files
//! directly between them. This example uses direct file transfer rather than the RE-VFS system.
//!
//! ## Features Demonstrated
//! - Direct P2P file transfer
//! - Binary data streaming
//! - Progress tracking
//! - Error handling for file operations
//!
//! ## Usage
//!
//! Run two instances - one sender and one receiver:
//! ```bash
//! # Sender
//! export CITADEL_MY_USER="sender"
//! export CITADEL_OTHER_USER="receiver"
//! export IS_SENDER="true"
//! cargo run --example file_transfer
//!
//! # Receiver (in another terminal)
//! export CITADEL_MY_USER="receiver"
//! export CITADEL_OTHER_USER="sender"
//! cargo run --example file_transfer
//! ```
//!
//! ## Note
//! This example demonstrates basic file transfer. For more advanced file operations,
//! see the RE-VFS examples which provide a virtual filesystem interface.

use citadel_sdk::{
    prefabs::client::peer_connection::{PeerConnectionKernel, PeerConnectionSetupAggregator},
    prelude::*,
};
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("CITADEL_SERVER_ADDR").expect("CITADEL_SERVER_ADDR not set");
    let my_user = env::var("CITADEL_MY_USER").expect("MY_USER not set");
    let other_user = env::var("CITADEL_OTHER_USER").expect("OTHER_USER not set");
    let is_sender = env::var("IS_SENDER").unwrap_or_default().to_lowercase() == "true";

    println!("Starting file transfer as peer {my_user}");
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

    let file_path = PathBuf::from("test_file.txt");
    if !file_path.exists() {
        tokio::fs::write(&file_path, "Hello, this is a test file!").await?;
    }

    // Set up the peer connection kernel
    let kernel = PeerConnectionKernel::new(
        server_connection_settings,
        peer_connection,
        move |mut connection, remote| async move {
            println!("Connected to server successfully!");

            // Wait for peer connection
            let peer_conn = connection.recv().await.unwrap()?;
            let peer_remote = peer_conn.remote;
            println!("Connected to peer {:?}!", peer_remote.target_username());
            if is_sender {
                peer_remote.send_file(file_path).await?;
            } else {
                let mut incoming_file_requests =
                    remote.get_incoming_file_transfer_handle().unwrap();
                let mut file_handle = incoming_file_requests.recv().await.unwrap();
                let downloaded_file = file_handle.receive_file().await?;
                // Compare the contents in "file_path" and "downloaded_file"
                let file_contents = tokio::fs::read_to_string(file_path).await?;
                let downloaded_file_contents = tokio::fs::read_to_string(downloaded_file).await?;
                assert_eq!(file_contents, downloaded_file_contents);
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
