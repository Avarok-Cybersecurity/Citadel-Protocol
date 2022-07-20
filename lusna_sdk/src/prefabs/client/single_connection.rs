use crate::prefabs::ClientServerRemote;
use crate::remote_ext::ConnectSuccess;
use crate::remote_ext::ProtocolRemoteExt;
use futures::Future;
use hyxe_net::auth::AuthenticationRequest;
use hyxe_net::prelude::*;
use parking_lot::Mutex;
use std::marker::PhantomData;
use std::net::SocketAddr;
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

        (handler)(
            connect_success,
            ClientServerRemote {
                inner: remote,
                conn_type,
            },
        )
        .await
    }

    async fn on_node_event_received(&self, _message: NodeResult) -> Result<(), NetworkError> {
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
    use crate::test_common::{server_info, server_info_reactive, wait_for_peers, TestBarrier};
    use rstest::rstest;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn single_connection_registered(
        #[values(UdpMode::Enabled, UdpMode::Disabled)] udp_mode: UdpMode,
        #[values(UnderlyingProtocol::new_quic_self_signed(), UnderlyingProtocol::new_tls_self_signed().unwrap())]
        underlying_protocol: UnderlyingProtocol,
    ) {
        let _ = lusna_logging::setup_log();
        TestBarrier::setup(2);

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        async fn on_server_received_conn(
            udp_mode: UdpMode,
            conn: ConnectSuccess,
            _remote: ClientServerRemote,
        ) -> Result<(), NetworkError> {
            wait_for_peers().await;
            crate::test_common::udp_mode_assertions(udp_mode, conn.udp_channel_rx).await;
            Ok(())
        }

        let (server, server_addr) = server_info_reactive(
            move |conn, remote| async move {
                on_server_received_conn(udp_mode, conn, remote).await?;
                server_success.store(true, Ordering::SeqCst);
                wait_for_peers().await;
                Ok(())
            },
            |builder| {
                let _ = builder
                    .server_config()
                    .with_underlying_protocol(underlying_protocol);
            },
        );

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let client_kernel = SingleClientServerConnectionKernel::new_register(
            "Thomas P Braun",
            "nologik",
            "password",
            server_addr,
            udp_mode,
            Default::default(),
            |channel, _remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
                wait_for_peers().await;
                crate::test_common::udp_mode_assertions(udp_mode, channel.udp_channel_rx).await;
                client_success.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                stop_tx.send(()).unwrap();
                Ok(())
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { let _ = res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(false)]
    #[case(true)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn single_connection_passwordless(#[case] debug_force_nat_timeout: bool) {
        let _ = lusna_logging::setup_log();

        if debug_force_nat_timeout {
            std::env::set_var("debug_cause_timeout", "ON");
        }

        let client_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let uuid = Uuid::new_v4();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless_defaults(
            uuid,
            server_addr,
            |_channel, _remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
                //_remote.inner.find_target("", "").await.unwrap().connect_to_peer().await.unwrap();
                client_success.store(true, Ordering::Relaxed);
                stop_tx.send(()).unwrap();
                Ok(())
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { let _ = res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }

        if debug_force_nat_timeout {
            std::env::remove_var("debug_cause_timeout");
        }

        assert!(client_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn single_connection_passwordless_deregister() {
        let _ = lusna_logging::setup_log();

        let client_success = &AtomicBool::new(false);
        let (server, server_addr) = server_info();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let uuid = Uuid::new_v4();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless_defaults(
            uuid,
            server_addr,
            |_channel, mut remote| async move {
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
                //_remote.inner.find_target("", "").await.unwrap().connect_to_peer().await.unwrap();
                remote.deregister().await?;
                client_success.store(true, Ordering::Relaxed);
                stop_tx.send(()).unwrap();
                Ok(())
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { let _ = res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }

        assert!(client_success.load(Ordering::Relaxed));
    }
}
