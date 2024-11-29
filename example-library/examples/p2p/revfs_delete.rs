//! # RE-VFS Delete Operation Example
//!
//! This example demonstrates how to use the Remote Encrypted Virtual Filesystem (RE-VFS)
//! to store files and then delete them. It shows the proper way to manage file cleanup
//! in the RE-VFS system.
//!
//! ## Features Demonstrated
//! - RE-VFS file storage
//! - Secure file deletion
//! - Permission handling for delete operations
//! - P2P connection establishment
//! - Error handling for file operations
//!
//! ## Usage
//! Run two instances - one sender and one with delete permissions:
//! ```bash
//! # Sender (stores file in RE-VFS)
//! export CITADEL_MY_USER="sender"
//! export CITADEL_OTHER_USER="manager"
//! export IS_SENDER="true"
//! cargo run --example revfs_delete
//!
//! # Manager (deletes file from RE-VFS)
//! export CITADEL_MY_USER="manager"
//! export CITADEL_OTHER_USER="sender"
//! cargo run --example revfs_delete
//! ```
//!
//! ## How it Works
//! 1. Sender stores a file in the RE-VFS
//! 2. Manager connects with appropriate permissions
//! 3. Manager issues delete command for the file
//! 4. File is permanently removed from RE-VFS
//!
//! ## Note
//! Delete operations are permanent and cannot be undone. Ensure proper
//! permissions and verification before deleting files from the RE-VFS.
//! Unlike the `revfs_take` example, this operation doesn't retrieve the
//! file before deletion.

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
            let (tx, mut rx) = peer_conn.channel.split();
            let peer_remote = peer_conn.remote;
            println!("Connected to peer {:?}!", peer_remote.target_username());

            let virtual_file_path = "/home/foo/bar/test_file.txt";

            if is_sender {
                // Securely store the file on the remote peer. The peer cannot read the file contents
                citadel_sdk::fs::write(&peer_remote, file_path.clone(), virtual_file_path).await?;
                // Now, delete the contents of the file from the remote peer
                citadel_sdk::fs::delete(&peer_remote, virtual_file_path).await?;
                // Alert the other side that the file has been successfully processed
                tx.send_message(SecBuffer::from("success").into()).await?;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            } else {
                let incoming_file_requests = remote.get_incoming_file_transfer_handle().unwrap();
                // There will be a single file transfer handles sent to us: one for the file the peer sends to us
                incoming_file_requests.accept_all();
                // Patiently wait for the "success" message from the sender
                let msg = rx.next().await.unwrap();
                assert_eq!(msg.as_ref(), b"success");
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
