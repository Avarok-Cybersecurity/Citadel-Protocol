//! # RE-VFS Take Operation Example
//!
//! This example demonstrates how to use the Remote Encrypted Virtual Filesystem (RE-VFS)
//! to store and then "take" a file. The take operation removes the file from the RE-VFS
//! while retrieving it, effectively performing an atomic move operation.
//!
//! ## Features Demonstrated
//! - RE-VFS file storage
//! - Atomic take operation (retrieve and delete)
//! - P2P connection establishment
//! - Secure file transfer
//! - Error handling for file operations
//!
//! ## Usage
//! Run two instances - one sender and one receiver:
//! ```bash
//! # Sender (stores file in RE-VFS)
//! export CITADEL_MY_USER="sender"
//! export CITADEL_OTHER_USER="receiver"
//! export IS_SENDER="true"
//! cargo run --example revfs_take
//!
//! # Receiver (takes file from RE-VFS)
//! export CITADEL_MY_USER="receiver"
//! export CITADEL_OTHER_USER="sender"
//! cargo run --example revfs_take
//! ```
//!
//! ## How it Works
//! 1. Sender stores a file in the RE-VFS
//! 2. Receiver connects and performs a take operation
//! 3. File is atomically moved from RE-VFS to receiver's local storage
//! 4. Original file in RE-VFS is automatically deleted
//!
//! ## Note
//! The take operation is useful when you want to ensure that a file can only be
//! retrieved once, or when you want to automatically clean up the RE-VFS after
//! file retrieval.

//! This example demonstrates how to set up a peer connection between two peers and use REVFS to store then take a file

use citadel_sdk::{
    prefabs::client::peer_connection::{PeerConnectionKernel, PeerConnectionSetupAggregator},
    prelude::*,
};
use futures::StreamExt;
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
    let server_connection_settings =
        DefaultServerConnectionSettingsBuilder::credentialed_registration(
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
            let (mut tx, mut rx) = peer_conn.channel.split();
            let peer_remote = peer_conn.remote;
            println!("Connected to peer {:?}!", peer_remote.target_username());

            let virtual_file_path = "/home/foo/bar/test_file.txt";

            if is_sender {
                // Securely store the file on the remote peer. The peer cannot read the file contents
                citadel_sdk::fs::write(&peer_remote, file_path.clone(), virtual_file_path).await?;
                // Now, download the contents of the file from the remote peer, deleting the remote
                // contents at the same time by taking it
                let locally_downloaded_file =
                    citadel_sdk::fs::take(&peer_remote, virtual_file_path).await?;
                // Compare the contents in "file_path" and "locally_downloaded_file"
                let file_contents = tokio::fs::read_to_string(&file_path).await?;
                let downloaded_file_contents =
                    tokio::fs::read_to_string(&locally_downloaded_file).await?;
                assert_eq!(file_contents, downloaded_file_contents);
                // Alert the other side that the file has been successfully processed
                tx.send(SecBuffer::from("success")).await?;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            } else {
                let incoming_file_requests = remote.get_incoming_file_transfer_handle().unwrap();
                // There will be two file transfer handles sent to us: one for the file the peer sends to us,
                // and another for when the peer requests a file from us. We will accept both.
                incoming_file_requests.accept_all();
                // Patiently wait for the "success" message from the sender
                let msg = rx.next().await.unwrap();
                assert_eq!(msg.as_ref(), b"success");
            }

            remote.shutdown_kernel().await
        },
    );

    // Build the peer
    let node = DefaultNodeBuilder::default().build(kernel)?;

    // Run the peer
    node.await?;

    Ok(())
}
