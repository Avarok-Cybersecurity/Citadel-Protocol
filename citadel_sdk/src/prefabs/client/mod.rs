use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use std::net::ToSocketAddrs;
use uuid::Uuid;

/// A kernel that assists in creating and/or connecting to a group
pub mod broadcast;
/// A kernel that assists in allowing multiple possible peer-to-peer connections
pub mod peer_connection;
/// A kernel that only makes a single client-to-server connection
pub mod single_connection;

#[async_trait]
pub trait PrefabFunctions<'a, Arg: Send + 'a>: Sized + 'a {
    type UserLevelInputFunction: Send + 'a;
    /// Shared between the kernel and the on_c2s_channel_received function
    type SharedBundle: Send + 'a;

    fn get_shared_bundle(&self) -> Self::SharedBundle;

    async fn on_c2s_channel_received(
        connect_success: ConnectionSuccess,
        remote: ClientServerRemote,
        arg: Arg,
        fx: Self::UserLevelInputFunction,
        shared: Self::SharedBundle,
    ) -> Result<(), NetworkError>;

    fn construct(kernel: Box<dyn NetKernel + 'a>) -> Self;

    /// Creates a new connection with a central server entailed by the user information
    fn new_connect<T: Into<String>, P: Into<SecBuffer>>(
        username: T,
        password: P,
        arg: Arg,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Self {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        let server_conn_kernel = SingleClientServerConnectionKernel::new_connect(
            username,
            password,
            udp_mode,
            session_security_settings,
            |connect_success, remote| {
                on_channel_received_fn::<_, Self>(
                    connect_success,
                    remote,
                    rx,
                    arg,
                    on_channel_received,
                )
            },
        );

        let this = Self::construct(Box::new(server_conn_kernel));
        assert!(tx.send(this.get_shared_bundle()).is_ok());
        this
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(
        username: T,
        password: P,
        arg: Arg,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Self {
        Self::new_connect(
            username,
            password,
            arg,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    #[allow(clippy::too_many_arguments)]
    fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>, V: ToSocketAddrs>(
        full_name: T,
        username: R,
        password: P,
        arg: Arg,
        server_addr: V,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Result<Self, NetworkError> {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        let server_conn_kernel = SingleClientServerConnectionKernel::new_register(
            full_name,
            username,
            password,
            server_addr,
            udp_mode,
            session_security_settings,
            |connect_success, remote| {
                on_channel_received_fn::<_, Self>(
                    connect_success,
                    remote,
                    rx,
                    arg,
                    on_channel_received,
                )
            },
        )?;

        let this = Self::construct(Box::new(server_conn_kernel));
        assert!(tx.send(this.get_shared_bundle()).is_ok());
        Ok(this)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    fn new_register_defaults<
        T: Into<String>,
        R: Into<String>,
        P: Into<SecBuffer>,
        V: ToSocketAddrs,
    >(
        full_name: T,
        username: R,
        password: P,
        arg: Arg,
        server_addr: V,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Result<Self, NetworkError> {
        Self::new_register(
            full_name,
            username,
            password,
            arg,
            server_addr,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }

    /// Creates a new authless connection with custom arguments
    fn new_passwordless<V: ToSocketAddrs>(
        uuid: Uuid,
        server_addr: V,
        arg: Arg,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Result<Self, NetworkError> {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        let server_conn_kernel = SingleClientServerConnectionKernel::new_passwordless(
            uuid,
            server_addr,
            udp_mode,
            session_security_settings,
            |connect_success, remote| {
                on_channel_received_fn::<_, Self>(
                    connect_success,
                    remote,
                    rx,
                    arg,
                    on_channel_received,
                )
            },
        )?;

        let this = Self::construct(Box::new(server_conn_kernel));
        assert!(tx.send(this.get_shared_bundle()).is_ok());
        Ok(this)
    }

    /// Creates a new authless connection with default arguments
    fn new_passwordless_defaults<V: ToSocketAddrs>(
        uuid: Uuid,
        server_addr: V,
        arg: Arg,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Result<Self, NetworkError> {
        Self::new_passwordless(
            uuid,
            server_addr,
            arg,
            Default::default(),
            Default::default(),
            on_channel_received,
        )
    }
}

async fn on_channel_received_fn<'a, Arg: Send + 'a, T: PrefabFunctions<'a, Arg>>(
    connect_success: ConnectionSuccess,
    remote: ClientServerRemote,
    rx_bundle: citadel_io::tokio::sync::oneshot::Receiver<T::SharedBundle>,
    arg: Arg,
    on_channel_received: T::UserLevelInputFunction,
) -> Result<(), NetworkError> {
    let shared = rx_bundle
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    T::on_c2s_channel_received(connect_success, remote, arg, on_channel_received, shared).await
}
