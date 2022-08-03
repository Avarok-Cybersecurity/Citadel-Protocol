use crate::prefabs::ClientServerRemote;
use crate::remote_ext::ConnectSuccess;
use crate::remote_ext::ProtocolRemoteExt;
use futures::Future;
use hyxe_net::auth::AuthenticationRequest;
use hyxe_net::prelude::*;
use parking_lot::Mutex;
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
    unprocessed_signal_filter_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<NodeResult>>>,
    remote: Option<NodeRemote>,
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
    F: FnOnce(ConnectSuccess, ClientServerRemote) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    /// Creates a new connection with a central server entailed by the user information
    pub fn new_connect<T: Into<String>, P: Into<SecBuffer>>(
        username: T,
        password: P,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: F,
    ) -> Self {
        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Connect {
                username: username.into(),
                password: password.into(),
            })),
            session_security_settings,
            unprocessed_signal_filter_tx: Default::default(),
            remote: None,
            _pd: Default::default(),
        }
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    pub fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(
        username: T,
        password: P,
        on_channel_received: F,
    ) -> Self {
        Self::new_connect(
            username,
            password,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    pub fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(
        full_name: T,
        username: R,
        password: P,
        server_addr: SocketAddr,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: F,
    ) -> Self {
        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Register {
                full_name: full_name.into(),
                server_addr,
                username: username.into(),
                password: password.into(),
            })),
            session_security_settings,
            unprocessed_signal_filter_tx: Default::default(),
            remote: None,
            _pd: Default::default(),
        }
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    pub fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(
        full_name: T,
        username: R,
        password: P,
        server_addr: SocketAddr,
        on_channel_received: F,
    ) -> Self {
        Self::new_register(
            full_name,
            username,
            password,
            server_addr,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }

    /// Creates a new authless connection with custom arguments
    pub fn new_passwordless(
        uuid: Uuid,
        server_addr: SocketAddr,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: F,
    ) -> Self {
        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Passwordless { uuid, server_addr })),
            session_security_settings,
            unprocessed_signal_filter_tx: Default::default(),
            remote: None,
            _pd: Default::default(),
        }
    }

    /// Creates a new authless connection with default arguments
    pub fn new_passwordless_defaults(
        uuid: Uuid,
        server_addr: SocketAddr,
        on_channel_received: F,
    ) -> Self {
        Self::new_passwordless(
            uuid,
            server_addr,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }
}

#[async_trait]
impl<F, Fut> NetKernel for SingleClientServerConnectionKernel<F, Fut>
where
    F: FnOnce(ConnectSuccess, ClientServerRemote) -> Fut + Send,
    Fut: Future<Output = Result<(), NetworkError>> + Send,
{
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.remote = Some(server_remote);
        Ok(())
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "lusna", skip_all, ret, err(Debug))
    )]
    async fn on_start(&self) -> Result<(), NetworkError> {
        let mut remote = self.remote.clone().unwrap();
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
            )
            .await?;
        let conn_type = VirtualTargetType::HyperLANPeerToHyperLANServer(connect_success.cid);

        let unprocessed_signal_filter = if cfg!(feature = "localhost-testing") {
            let (reroute_tx, reroute_rx) = tokio::sync::mpsc::unbounded_channel();
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
            },
        )
        .await
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        if let Some(val) = self.unprocessed_signal_filter_tx.lock().as_ref() {
            log::info!(target: "lusna", "Will forward message {:?}", val);
            if let Err(err) = val.send(message) {
                log::warn!(target: "lusna", "failed to send unprocessed NodeResult: {:?}", err)
            }
        } else {
            log::info!(target: "lusna", "ASDFKL");
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
    use crate::prefabs::ClientServerRemote;
    use crate::prelude::*;
    use crate::test_common::{server_info_reactive, wait_for_peers, TestBarrier};
    use rstest::rstest;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "lusna", skip_all, err(Debug))
    )]
    async fn on_server_received_conn(
        udp_mode: UdpMode,
        conn: ConnectSuccess,
        _remote: ClientServerRemote,
    ) -> Result<(), NetworkError> {
        crate::test_common::udp_mode_assertions(udp_mode, conn.udp_channel_rx).await;
        Ok(())
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "lusna", skip_all, err(Debug))
    )]
    async fn default_server_harness(
        udp_mode: UdpMode,
        conn: ConnectSuccess,
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
    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_registered(
        #[values(UdpMode::Enabled, UdpMode::Disabled)] udp_mode: UdpMode,
        #[values(UnderlyingProtocol::new_quic_self_signed(), UnderlyingProtocol::new_tls_self_signed().unwrap())]
        underlying_protocol: UnderlyingProtocol,
    ) {
        let _ = lusna_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info_reactive(
            move |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |builder| {
                let _ = builder
                    .server_config()
                    .with_underlying_protocol(underlying_protocol);
            },
        );

        let client_kernel = SingleClientServerConnectionKernel::new_register(
            "Thomas P Braun",
            "nologik",
            "password",
            server_addr,
            udp_mode,
            Default::default(),
            |channel, remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
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
    #[case(false, UdpMode::Enabled)]
    #[case(true, UdpMode::Disabled)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_passwordless(
        #[case] debug_force_nat_timeout: bool,
        #[case] udp_mode: UdpMode,
    ) {
        let _ = lusna_logging::setup_log();
        TestBarrier::setup(2);

        if debug_force_nat_timeout {
            std::env::set_var("debug_cause_timeout", "ON");
        }

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info_reactive(
            |conn, remote| async move {
                default_server_harness(udp_mode, conn, remote, server_success).await
            },
            |_| (),
        );

        let uuid = Uuid::new_v4();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless(
            uuid,
            server_addr,
            udp_mode,
            Default::default(),
            |channel, remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
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

        if debug_force_nat_timeout {
            std::env::remove_var("debug_cause_timeout");
        }

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(UdpMode::Disabled)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_connection_passwordless_deregister(#[case] udp_mode: UdpMode) {
        let _ = lusna_logging::setup_log();
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

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless(
            uuid,
            server_addr,
            udp_mode,
            Default::default(),
            |channel, mut remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
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
}
