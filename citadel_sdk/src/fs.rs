use crate::prelude::{ObjectSource, ProtocolRemoteTargetExt, TargetLockedRemote};

use citadel_proto::prelude::NetworkError;
use citadel_types::crypto::SecurityLevel;
use std::path::PathBuf;

/// Writes a file or BytesSource to the Remote Encrypted Virtual Filesystem
pub async fn write<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    source: T,
    virtual_path: R,
) -> Result<(), NetworkError> {
    write_with_security_level(remote, source, Default::default(), virtual_path).await
}

/// Writes a file or BytesSource to the Remote Encrypted Virtual Filesystem with a custom security level.
pub async fn write_with_security_level<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    source: T,
    security_level: SecurityLevel,
    virtual_path: R,
) -> Result<(), NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_push(source, virtual_path, security_level)
        .await
}

/// Reads a file from the Remote Encrypted Virtual Filesystem
pub async fn read<R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    virtual_path: R,
) -> Result<PathBuf, NetworkError> {
    read_with_security_level(remote, Default::default(), virtual_path).await
}

/// Reads a file from the Remote Encrypted Virtual Filesystem with a custom transport security level
pub async fn read_with_security_level<R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    transfer_security_level: SecurityLevel,
    virtual_path: R,
) -> Result<PathBuf, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, transfer_security_level, false)
        .await
}

/// Takes a file from the Remote Encrypted Virtual Filesystem
pub async fn take<R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    virtual_path: R,
) -> Result<PathBuf, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, Default::default(), true)
        .await
}

/// Takes a file from the Remote Encrypted Virtual Filesystem with a custom security level.
pub async fn take_with_security_level<R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    transfer_security_level: SecurityLevel,
    virtual_path: R,
) -> Result<PathBuf, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, transfer_security_level, true)
        .await
}

/// Deletes a file from the Remote Encrypted Virtual Filesystem
pub async fn delete<R: Into<PathBuf> + Send>(
    remote: &impl TargetLockedRemote,
    virtual_path: R,
) -> Result<(), NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_delete(virtual_path)
        .await
}

#[cfg(test)]
mod tests {
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use crate::prefabs::server::accept_file_transfer_kernel::AcceptFileTransferKernel;

    use crate::prefabs::client::peer_connection::{FileTransferHandleRx, PeerConnectionKernel};
    use crate::prefabs::client::ServerConnectionSettingsBuilder;
    use crate::prelude::*;
    use crate::test_common::wait_for_peers;
    use citadel_io::tokio;
    use futures::StreamExt;
    use rstest::rstest;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    pub fn server_info<'a>() -> (NodeFuture<'a, AcceptFileTransferKernel>, SocketAddr) {
        crate::test_common::server_test_node(AcceptFileTransferKernel, |_| {})
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[case(
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::Kyber,
        SigAlgorithm::None
    )]
    #[case(
        EncryptionAlgorithm::Kyber,
        KemAlgorithm::Kyber,
        SigAlgorithm::Falcon1024
    )]
    #[citadel_io::tokio::test]
    async fn test_c2s_file_transfer_revfs(
        #[case] enx: EncryptionAlgorithm,
        #[case] kem: KemAlgorithm,
        #[case] sig: SigAlgorithm,
        #[values(SecurityLevel::Standard, SecurityLevel::Reinforced)] security_level: SecurityLevel,
    ) {
        citadel_logging::setup_log();
        let client_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info();
        let uuid = Uuid::new_v4();

        let source_dir = PathBuf::from("../resources/TheBridge.pdf");

        let session_security_settings = SessionSecuritySettingsBuilder::default()
            .with_crypto_params(enx + kem + sig)
            .with_security_level(security_level)
            .build()
            .unwrap();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
                .disable_udp()
                .with_session_security_settings(session_security_settings)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                let virtual_path = PathBuf::from("/home/john.doe/TheBridge.pdf");
                // write to file to the RE-VFS
                crate::fs::write_with_security_level(
                    &remote,
                    source_dir.clone(),
                    security_level,
                    &virtual_path,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT FILE TRANSFER SUCCESS***");
                // now, pull it
                let save_dir = crate::fs::read(&remote, virtual_path).await?;
                // now, compare bytes
                log::trace!(target: "citadel", "***CLIENT REVFS PULL SUCCESS");
                let original_bytes = citadel_io::tokio::fs::read(&source_dir).await.unwrap();
                let revfs_pulled_bytes = citadel_io::tokio::fs::read(&save_dir).await.unwrap();
                assert_eq!(original_bytes, revfs_pulled_bytes);
                log::trace!(target: "citadel", "***CLIENT REVFS PULL COMPARE SUCCESS");
                client_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let result = citadel_io::tokio::select! {
            res0 = client => res0.map(|_| ()),
            res1 = server => res1.map(|_| ())
        };

        result.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[case(
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::Kyber,
        SigAlgorithm::None
    )]
    #[citadel_io::tokio::test]
    async fn test_c2s_file_transfer_revfs_take(
        #[case] enx: EncryptionAlgorithm,
        #[case] kem: KemAlgorithm,
        #[case] sig: SigAlgorithm,
        #[values(SecurityLevel::Standard)] security_level: SecurityLevel,
    ) {
        citadel_logging::setup_log();
        let client_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info();
        let uuid = Uuid::new_v4();

        let source_dir = PathBuf::from("../resources/TheBridge.pdf");

        let session_security_settings = SessionSecuritySettingsBuilder::default()
            .with_crypto_params(enx + kem + sig)
            .with_security_level(security_level)
            .build()
            .unwrap();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
                .disable_udp()
                .with_session_security_settings(session_security_settings)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                let virtual_path = PathBuf::from("/home/john.doe/TheBridge.pdf");
                // write to file to the RE-VFS
                crate::fs::write_with_security_level(
                    &remote,
                    source_dir.clone(),
                    security_level,
                    &virtual_path,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT FILE TRANSFER SUCCESS***");
                // now, pull it
                let save_dir = crate::fs::take(&remote, &virtual_path).await?;
                // now, compare bytes
                log::trace!(target: "citadel", "***CLIENT REVFS PULL SUCCESS");
                let original_bytes = citadel_io::tokio::fs::read(&source_dir).await.unwrap();
                let revfs_pulled_bytes = citadel_io::tokio::fs::read(&save_dir).await.unwrap();
                assert_eq!(original_bytes, revfs_pulled_bytes);
                log::trace!(target: "citadel", "***CLIENT REVFS PULL COMPARE SUCCESS");
                // prove we can no longer read from this virtual file
                assert!(crate::fs::read(&remote, &virtual_path).await.is_err());
                client_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let result = citadel_io::tokio::select! {
            res0 = client => res0.map(|_| ()),
            res1 = server => res1.map(|_| ())
        };

        result.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[case(
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::Kyber,
        SigAlgorithm::None
    )]
    #[citadel_io::tokio::test]
    async fn test_c2s_file_transfer_revfs_delete(
        #[case] enx: EncryptionAlgorithm,
        #[case] kem: KemAlgorithm,
        #[case] sig: SigAlgorithm,
        #[values(SecurityLevel::Standard)] security_level: SecurityLevel,
    ) {
        citadel_logging::setup_log();
        let client_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info();
        let uuid = Uuid::new_v4();

        let source_dir = PathBuf::from("../resources/TheBridge.pdf");

        let session_security_settings = SessionSecuritySettingsBuilder::default()
            .with_crypto_params(enx + kem + sig)
            .with_security_level(security_level)
            .build()
            .unwrap();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
                .disable_udp()
                .with_session_security_settings(session_security_settings)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                let virtual_path = PathBuf::from("/home/john.doe/TheBridge.pdf");
                // write to file to the RE-VFS
                crate::fs::write_with_security_level(
                    &remote,
                    source_dir.clone(),
                    security_level,
                    &virtual_path,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT FILE TRANSFER SUCCESS***");
                // now, pull it
                let save_dir = crate::fs::read(&remote, &virtual_path).await?;
                // now, compare bytes
                log::trace!(target: "citadel", "***CLIENT REVFS PULL SUCCESS");
                let original_bytes = citadel_io::tokio::fs::read(&source_dir).await.unwrap();
                let revfs_pulled_bytes = citadel_io::tokio::fs::read(&save_dir).await.unwrap();
                assert_eq!(original_bytes, revfs_pulled_bytes);
                log::trace!(target: "citadel", "***CLIENT REVFS PULL COMPARE SUCCESS");
                crate::fs::delete(&remote, &virtual_path).await?;
                // prove we can no longer read from this virtual file since it was just deleted
                assert!(crate::fs::read(&remote, &virtual_path).await.is_err());
                client_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let result = citadel_io::tokio::select! {
            res0 = client => res0.map(|_| ()),
            res1 = server => res1.map(|_| ())
        };

        result.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(SecrecyMode::BestEffort)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_p2p_file_transfer_revfs(
        #[case] secrecy_mode: SecrecyMode,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(EncryptionAlgorithm::AES_GCM_256)] enx: EncryptionAlgorithm,
    ) {
        citadel_logging::setup_log();
        crate::test_common::TestBarrier::setup(2);
        let client0_success = &AtomicBool::new(false);
        let client1_success = &AtomicBool::new(false);

        let (server, server_addr) = crate::test_common::server_info();

        let uuid0 = Uuid::new_v4();
        let uuid1 = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build()
            .unwrap();

        let security_level = SecurityLevel::Standard;

        let source_dir = &PathBuf::from("../resources/TheBridge.pdf");

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid0)
                .disable_udp()
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        // TODO: SinglePeerConnectionKernel
        let client_kernel0 = PeerConnectionKernel::new(
            server_connection_settings,
            uuid1,
            move |mut connection, remote_outer| async move {
                wait_for_peers().await;
                let mut connection = connection.recv().await.unwrap()?;
                wait_for_peers().await;
                // The other peer will send the file first
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                let handle_orig = connection.incoming_object_transfer_handles.take().unwrap();
                accept_all(handle_orig);
                wait_for_peers().await;
                client0_success.store(true, Ordering::Relaxed);
                remote_outer.shutdown_kernel().await
            },
        );

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid1)
                .disable_udp()
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel1 = PeerConnectionKernel::new(
            server_connection_settings,
            uuid0,
            move |mut connection, remote_outer| async move {
                wait_for_peers().await;
                let connection = connection.recv().await.unwrap()?;
                wait_for_peers().await;
                let remote = connection.remote.clone();
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                let virtual_path = PathBuf::from("/home/john.doe/TheBridge.pdf");
                // write the file to the RE-VFS
                crate::fs::write_with_security_level(
                    &remote,
                    source_dir.clone(),
                    security_level,
                    &virtual_path,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT FILE TRANSFER SUCCESS***");
                // now, pull it
                let save_dir = crate::fs::read(&remote, virtual_path).await?;
                // now, compare bytes
                log::trace!(target: "citadel", "***CLIENT REVFS PULL SUCCESS");
                let original_bytes = citadel_io::tokio::fs::read(&source_dir).await.unwrap();
                let revfs_pulled_bytes = citadel_io::tokio::fs::read(&save_dir).await.unwrap();
                assert_eq!(original_bytes, revfs_pulled_bytes);
                log::trace!(target: "citadel", "***CLIENT REVFS PULL COMPARE SUCCESS");
                wait_for_peers().await;
                client1_success.store(true, Ordering::Relaxed);
                remote_outer.shutdown_kernel().await
            },
        );

        let client0 = NodeBuilder::default().build(client_kernel0).unwrap();
        let client1 = NodeBuilder::default().build(client_kernel1).unwrap();
        let clients = futures::future::try_join(client0, client1);

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let _ = citadel_io::tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .unwrap();

        assert!(client0_success.load(Ordering::Relaxed));
        assert!(client1_success.load(Ordering::Relaxed));
    }

    fn accept_all(mut rx: FileTransferHandleRx) {
        let handle = citadel_io::tokio::task::spawn(async move {
            while let Some(mut handle) = rx.recv().await {
                let _ = handle.accept();
                // Exhaust the stream
                let handle = citadel_io::tokio::task::spawn(async move {
                    while let Some(evt) = handle.next().await {
                        if let ObjectTransferStatus::Fail(err) = evt {
                            log::error!(target: "citadel", "File Transfer Failed: {err:?}");
                            std::process::exit(1);
                        }
                    }
                });

                drop(handle);
            }
        });

        drop(handle);
    }
}
