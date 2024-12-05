//! Single Client-Server Connection Kernel
//!
//! This module implements a network kernel for managing a single client-to-server connection
//! in the Citadel Protocol. It provides NAT traversal, peer discovery, and secure
//! communication channels between clients and a central server.
//!
//! # Features
//! - Multiple authentication modes (Credentials, Transient)
//! - NAT traversal support with configurable UDP mode
//! - Secure session management with customizable security settings
//! - Object transfer handling for file/data exchange
//! - Pre-shared key authentication for server access
//! - Automatic connection lifecycle management
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
//!
//! # fn main() -> Result<(), NetworkError> {
//! async fn connect_to_server() -> Result<(), NetworkError> {
//!     let settings = DefaultServerConnectionSettingsBuilder::transient("127.0.0.1:25021")
//!         .with_udp_mode(UdpMode::Enabled)
//!         .build()?;
//!     
//!     let kernel = SingleClientServerConnectionKernel::new(
//!         settings,
//!         |conn, remote| async move {
//!             println!("Connected to server!");
//!             Ok(())
//!         },
//!     );
//!     
//!     Ok(())
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - Only manages a single server connection at a time
//! - Connection handler must be Send + Future
//! - UDP mode affects NAT traversal capabilities
//! - Object transfer requires proper handler setup
//!
//! # Related Components
//! - [`NetKernel`]: Base trait for network kernels
//! - [`ServerConnectionSettings`]: Connection configuration
//! - [`ClientServerRemote`]: Remote connection handler
//! - [`ConnectionSuccess`]: Connection establishment data
//!

use crate::prefabs::client::peer_connection::FileTransferHandleRx;
use crate::prefabs::client::ServerConnectionSettings;
use crate::prefabs::ClientServerRemote;
use crate::remote_ext::ConnectionSuccess;
use crate::remote_ext::ProtocolRemoteExt;
use citadel_io::Mutex;
use citadel_proto::prelude::*;
use futures::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use uuid::Uuid;

/// This [`SingleClientServerConnectionKernel`] is the base kernel type for other built-in implementations of [`NetKernel`].
/// It establishes connections to a central node for purposes of NAT traversal and peer discovery, and depending on the application layer,
/// can leverage the client to server connection for other purposes that require communication between the two.
pub struct SingleClientServerConnectionKernel<F, Fut, R: Ratchet> {
    handler: Mutex<Option<F>>,
    udp_mode: UdpMode,
    auth_info: Mutex<Option<ConnectionType>>,
    session_security_settings: SessionSecuritySettings,
    unprocessed_signal_filter_tx:
        Mutex<Option<citadel_io::tokio::sync::mpsc::UnboundedSender<NodeResult>>>,
    remote: Option<NodeRemote<R>>,
    server_password: Option<PreSharedKey>,
    rx_incoming_object_transfer_handle: Mutex<Option<FileTransferHandleRx>>,
    tx_incoming_object_transfer_handle:
        citadel_io::tokio::sync::mpsc::UnboundedSender<ObjectTransferHandler>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> Fut>,
}

#[derive(Debug)]
pub(crate) enum ConnectionType {
    Register {
        server_addr: SocketAddr,
        username: String,
        password: SecBuffer,
        full_name: String,
    },
    Connect {
        username: String,
        password: SecBuffer,
    },
    Transient {
        uuid: Uuid,
        server_addr: SocketAddr,
    },
}

impl<F, Fut, R: Ratchet> SingleClientServerConnectionKernel<F, Fut, R>
where
    F: FnOnce(ConnectionSuccess, ClientServerRemote<R>) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    fn generate_object_transfer_handle() -> (
        citadel_io::tokio::sync::mpsc::UnboundedSender<ObjectTransferHandler>,
        Mutex<Option<FileTransferHandleRx>>,
    ) {
        let (tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        let rx = FileTransferHandleRx {
            inner: rx,
            conn_type: VirtualTargetType::LocalGroupServer { session_cid: 0 },
        };
        (tx, Mutex::new(Some(rx)))
    }

    /// Creates a new [`SingleClientServerConnectionKernel`] with the given settings.
    /// The [`ServerConnectionSettings`] must be provided, and the `on_channel_received` function will be called when the connection is established.
    pub fn new(settings: ServerConnectionSettings<R>, on_channel_received: F) -> Self {
        let (udp_mode, session_security_settings) =
            (settings.udp_mode(), settings.session_security_settings());
        let server_password = settings.pre_shared_key().cloned();
        let (tx_incoming_object_transfer_handle, rx_incoming_object_transfer_handle) =
            Self::generate_object_transfer_handle();

        let connection_type = match settings {
            ServerConnectionSettings::CredentialedConnect {
                username, password, ..
            } => ConnectionType::Connect { username, password },

            ServerConnectionSettings::Transient {
                server_addr: address,
                uuid,
                ..
            } => ConnectionType::Transient {
                uuid,
                server_addr: address,
            },

            ServerConnectionSettings::CredentialedRegister {
                alias,
                username,
                password,
                address,
                ..
            } => ConnectionType::Register {
                full_name: alias,
                server_addr: address,
                username,
                password,
            },
        };

        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(connection_type)),
            session_security_settings,
            unprocessed_signal_filter_tx: Default::default(),
            rx_incoming_object_transfer_handle,
            tx_incoming_object_transfer_handle,
            server_password,
            remote: None,
            _pd: Default::default(),
        }
    }
}

#[async_trait]
impl<F, Fut, R: Ratchet> NetKernel<R> for SingleClientServerConnectionKernel<F, Fut, R>
where
    F: FnOnce(ConnectionSuccess, ClientServerRemote<R>) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    fn load_remote(&mut self, server_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.remote = Some(server_remote);
        Ok(())
    }

    #[allow(clippy::blocks_in_conditions)]
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, err(Debug))
    )]
    async fn on_start(&self) -> Result<(), NetworkError> {
        let session_security_settings = self.session_security_settings;
        let remote = self.remote.clone().unwrap();
        let (auth_info, handler) = {
            (
                self.auth_info.lock().take().unwrap(),
                self.handler.lock().take().unwrap(),
            )
        };

        let auth = match auth_info {
            ConnectionType::Register {
                full_name,
                server_addr,
                username,
                password,
            } => {
                if !remote
                    .account_manager()
                    .get_persistence_handler()
                    .username_exists(&username)
                    .await?
                {
                    let _reg_success = remote
                        .register(
                            server_addr,
                            full_name.as_str(),
                            username.as_str(),
                            password.clone(),
                            self.session_security_settings,
                            self.server_password.clone(),
                        )
                        .await?;
                }

                AuthenticationRequest::credentialed(username, password)
            }

            ConnectionType::Connect { username, password } => {
                AuthenticationRequest::credentialed(username, password)
            }

            ConnectionType::Transient { uuid, server_addr } => {
                AuthenticationRequest::transient(uuid, server_addr)
            }
        };

        let connect_success = remote
            .connect(
                auth,
                Default::default(),
                self.udp_mode,
                None,
                self.session_security_settings,
                self.server_password.clone(),
            )
            .await?;
        let conn_type = VirtualTargetType::LocalGroupServer {
            session_cid: connect_success.cid,
        };

        let mut handle = {
            let mut lock = self.rx_incoming_object_transfer_handle.lock();
            lock.take().expect("Should not have been called before")
        };

        handle.conn_type.set_session_cid(connect_success.cid);

        let (reroute_tx, reroute_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        *self.unprocessed_signal_filter_tx.lock() = Some(reroute_tx);

        handler(
            connect_success,
            ClientServerRemote::new(
                conn_type,
                remote,
                session_security_settings,
                Some(reroute_rx),
                Some(handle),
            ),
        )
        .await
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        match message {
            NodeResult::ObjectTransferHandle(handle) => {
                if let Err(err) = self.tx_incoming_object_transfer_handle.send(handle.handle) {
                    log::warn!(target: "citadel", "failed to send unprocessed NodeResult: {:?}", err)
                }
            }

            message => {
                if let Some(val) = self.unprocessed_signal_filter_tx.lock().as_ref() {
                    log::trace!(target: "citadel", "Will forward message {:?}", val);
                    if let Err(err) = val.send(message) {
                        log::warn!(target: "citadel", "failed to send unprocessed NodeResult: {:?}", err)
                    }
                }
            }
        }

        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use crate::prefabs::ClientServerRemote;
    use crate::prelude::*;
    use crate::test_common::{server_info_reactive, wait_for_peers, TestBarrier};
    use citadel_io::tokio;
    use rstest::rstest;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, err(Debug))
    )]
    async fn on_server_received_conn(
        udp_mode: UdpMode,
        conn: ConnectionSuccess,
    ) -> Result<(), NetworkError> {
        crate::test_common::udp_mode_assertions(udp_mode, conn.udp_channel_rx).await;
        Ok(())
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, err(Debug))
    )]
    async fn default_server_harness<R: Ratchet>(
        udp_mode: UdpMode,
        conn: ConnectionSuccess,
        remote: ClientServerRemote<R>,
        server_success: &AtomicBool,
    ) -> Result<(), NetworkError> {
        wait_for_peers().await;
        on_server_received_conn(udp_mode, conn).await?;
        server_success.store(true, Ordering::SeqCst);
        wait_for_peers().await;
        remote.shutdown_kernel().await
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_registered(
        #[values(UdpMode::Enabled, UdpMode::Disabled)] udp_mode: UdpMode,
        #[values(ServerUnderlyingProtocol::new_quic_self_signed(), ServerUnderlyingProtocol::new_tls_self_signed().unwrap()
        )]
        underlying_protocol: ServerUnderlyingProtocol,
    ) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        // If the underlying protocol is TLS, we will skip since windows runners do not always accept self-signed certs
        if matches!(underlying_protocol, ServerUnderlyingProtocol::Tls(..)) && cfg!(windows) {
            citadel_logging::warn!(target: "citadel", "Will skip test since self-signed certs may not necessarily work on windows runner");
            return;
        }

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |builder| {
                let _ = builder.with_underlying_protocol(underlying_protocol);
            },
        );

        let client_settings = DefaultServerConnectionSettingsBuilder::credentialed_registration(
            server_addr,
            "nologik",
            "Some Alias",
            "password",
        )
        .with_udp_mode(udp_mode)
        .build()
        .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            client_settings,
            |channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;
                crate::test_common::udp_mode_assertions(udp_mode, channel.udp_channel_rx).await;
                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(UdpMode::Enabled, None)]
    #[case(UdpMode::Enabled, Some("test-password"))]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_transient(
        #[case] udp_mode: UdpMode,
        #[case] server_password: Option<&'static str>,
    ) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |opts| {
                if let Some(password) = server_password {
                    let _ = opts.with_server_password(password);
                }
            },
        );

        let uuid = Uuid::new_v4();

        let mut server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(udp_mode);

        if let Some(server_password) = server_password {
            server_connection_settings =
                server_connection_settings.with_session_password(server_password);
        }

        let server_connection_settings = server_connection_settings.build().unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;
                crate::test_common::udp_mode_assertions(udp_mode, channel.udp_channel_rx).await;
                remote.disconnect().await?;
                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(UdpMode::Enabled, Some("test-password"))]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_transient_wrong_password(
        #[case] udp_mode: UdpMode,
        #[case] server_password: Option<&'static str>,
    ) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |_conn, _remote| async move { panic!("Server should not have connected") },
            |opts| {
                if let Some(password) = server_password {
                    let _ = opts.with_server_password(password);
                }
            },
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .with_session_password("wrong-password")
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, _remote| async move { panic!("Client should not have connected") },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        tokio::select! {
            _res0 = server => {
                panic!("Server should never finish")
            },

            result = client => {
                if let Err(error) = result {
                    assert!(error.into_string().contains("EncryptionFailure"));
                } else {
                    panic!("Client should not have connected")
                }
            }
        }
    }

    #[rstest]
    #[case(UdpMode::Disabled)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_transient_deregister(#[case] udp_mode: UdpMode) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;
                crate::test_common::udp_mode_assertions(udp_mode, channel.udp_channel_rx).await;
                remote.deregister().await?;
                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_backend_store_c2s() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let udp_mode = UdpMode::Disabled;

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;

                const KEY: &str = "HELLO_WORLD";
                const KEY2: &str = "HELLO_WORLD2";
                let value: Vec<u8> = Vec::from("Hello, world!");
                let value2: Vec<u8> = Vec::from("Hello, world!2");

                assert_eq!(remote.set(KEY, value.clone()).await?.as_deref(), None);
                assert_eq!(remote.get(KEY).await?.as_deref(), Some(value.as_slice()));

                assert_eq!(remote.set(KEY2, value2.clone()).await?.as_deref(), None);
                assert_eq!(remote.get(KEY2).await?.as_deref(), Some(value2.as_slice()));

                let map = remote.get_all().await?;
                assert_eq!(map.get(KEY), Some(&value));
                assert_eq!(map.get(KEY2), Some(&value2));

                assert_eq!(
                    remote.remove(KEY2).await?.as_deref(),
                    Some(value2.as_slice())
                );

                assert_eq!(remote.remove(KEY2).await?.as_deref(), None);

                let map = remote.remove_all().await?;
                assert_eq!(map.get(KEY), Some(&value));
                assert_eq!(map.get(KEY2), None);

                assert_eq!(remote.get_all().await?.len(), 0);
                assert_eq!(remote.remove_all().await?.len(), 0);

                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_rekey_c2s() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let udp_mode = UdpMode::Disabled;

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;

                for x in 1..10 {
                    assert_eq!(remote.rekey().await?, Some(x));
                }

                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;

                remote.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }
}
