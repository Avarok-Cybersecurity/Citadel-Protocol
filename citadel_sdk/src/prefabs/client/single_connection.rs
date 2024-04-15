use crate::prefabs::client::ServerConnectionSettings;
use crate::prefabs::ClientServerRemote;
use crate::remote_ext::ConnectionSuccess;
use crate::remote_ext::ProtocolRemoteExt;
use citadel_io::Mutex;
use citadel_proto::prelude::*;
use futures::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account.
///
/// This [`NetKernel`] is the base kernel type for other built-in implementations of [`NetKernel`]
pub struct SingleClientServerConnectionKernel<F, Fut> {
    handler: Mutex<Option<F>>,
    udp_mode: UdpMode,
    auth_info: Mutex<Option<ConnectionType>>,
    session_security_settings: SessionSecuritySettings,
    unprocessed_signal_filter_tx:
        Mutex<Option<citadel_io::tokio::sync::mpsc::UnboundedSender<NodeResult>>>,
    remote: Option<NodeRemote>,
    server_password: Option<PreSharedKey>,
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
    Passwordless {
        uuid: Uuid,
        server_addr: SocketAddr,
    },
}

impl<F, Fut> SingleClientServerConnectionKernel<F, Fut>
where
    F: FnOnce(ConnectionSuccess, ClientServerRemote) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    /// Creates a new [`SingleClientServerConnectionKernel`] with the given settings.
    /// The [`ServerConnectionSettings`] must be provided, and the [`on_channel_received`] function will be called when the connection is established.
    pub fn new(settings: ServerConnectionSettings, on_channel_received: F) -> Self {
        let (udp_mode, session_security_settings) =
            (settings.udp_mode(), settings.session_security_settings());
        let server_password = settings.pre_shared_key().cloned();

        let connection_type = match settings {
            ServerConnectionSettings::CredentialedConnect {
                username, password, ..
            } => ConnectionType::Connect { username, password },

            ServerConnectionSettings::NoCredentials {
                server_addr: address,
                uuid,
                ..
            } => ConnectionType::Passwordless {
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
            remote: None,
            server_password,
            _pd: Default::default(),
        }
    }
}

#[async_trait]
impl<F, Fut> NetKernel for SingleClientServerConnectionKernel<F, Fut>
where
    F: FnOnce(ConnectionSuccess, ClientServerRemote) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
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

            ConnectionType::Passwordless { uuid, server_addr } => {
                AuthenticationRequest::passwordless(uuid, server_addr)
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
            implicated_cid: connect_success.cid,
        };

        let unprocessed_signal_filter = if cfg!(feature = "localhost-testing") {
            let (reroute_tx, reroute_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
            *self.unprocessed_signal_filter_tx.lock() = Some(reroute_tx);
            Some(reroute_rx)
        } else {
            None
        };

        (handler)(
            connect_success,
            ClientServerRemote {
                inner: remote,
                unprocessed_signals_rx: Arc::new(Mutex::new(unprocessed_signal_filter)),
                conn_type,
                session_security_settings,
            },
        )
        .await
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        if let Some(val) = self.unprocessed_signal_filter_tx.lock().as_ref() {
            log::info!(target: "citadel", "Will forward message {:?}", val);
            if let Err(err) = val.send(message) {
                log::warn!(target: "citadel", "failed to send unprocessed NodeResult: {:?}", err)
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
    use crate::prefabs::client::ServerConnectionSettingsBuilder;
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
        _remote: ClientServerRemote,
    ) -> Result<(), NetworkError> {
        crate::test_common::udp_mode_assertions(udp_mode, conn.udp_channel_rx).await;
        Ok(())
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, err(Debug))
    )]
    async fn default_server_harness(
        udp_mode: UdpMode,
        conn: ConnectionSuccess,
        remote: ClientServerRemote,
        server_success: &AtomicBool,
    ) -> Result<(), NetworkError> {
        wait_for_peers().await;
        on_server_received_conn(udp_mode, conn, remote.clone()).await?;
        server_success.store(true, Ordering::SeqCst);
        wait_for_peers().await;
        remote.shutdown_kernel().await
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_registered(
        #[values(UdpMode::Enabled, UdpMode::Disabled)] udp_mode: UdpMode,
        #[values(ServerUnderlyingProtocol::new_quic_self_signed(), ServerUnderlyingProtocol::new_tls_self_signed().unwrap())]
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

        let (server, server_addr) = server_info_reactive(
            move |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |builder| {
                let _ = builder.with_underlying_protocol(underlying_protocol);
            },
        );

        let client_settings = ServerConnectionSettingsBuilder::credentialed_registration(
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

        let client = NodeBuilder::default().build(client_kernel).unwrap();

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
    async fn test_single_connection_passwordless(
        #[case] udp_mode: UdpMode,
        #[case] server_password: Option<&'static str>,
    ) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info_reactive(
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
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
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

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(UdpMode::Enabled, Some("test-password"))]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_passwordless_wrong_password(
        #[case] udp_mode: UdpMode,
        #[case] server_password: Option<&'static str>,
    ) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let (server, server_addr) = server_info_reactive(
            |_conn, _remote| async move { panic!("Server should not have connected") },
            |opts| {
                if let Some(password) = server_password {
                    let _ = opts.with_server_password(password);
                }
            },
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .with_session_password("wrong-password")
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |_channel, _remote| async move { panic!("Client should not have connected") },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

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
    async fn test_single_connection_passwordless_deregister(#[case] udp_mode: UdpMode) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info_reactive(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
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

        let client = NodeBuilder::default().build(client_kernel).unwrap();

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
        let (server, server_addr) = server_info_reactive(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
                .with_udp_mode(udp_mode)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |channel, remote| async move {
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;
                crate::test_common::udp_mode_assertions(udp_mode, channel.udp_channel_rx).await;

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

        let client = NodeBuilder::default().build(client_kernel).unwrap();

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
        let (server, server_addr) = server_info_reactive(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::no_credentials(server_addr, uuid)
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

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }
}
