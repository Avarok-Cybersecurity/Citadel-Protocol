use crate::prelude::*;
use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prefabs::ClientServerRemote;
use uuid::Uuid;
use std::net::SocketAddr;

/// A kernel that only makes a single client-to-server connection
pub mod single_connection;
/// A kernel that assists in allowing multiple possible peer-to-peer connections
pub mod peer_connection;
/// A kernel that assists in creating and/or connecting to a group
pub mod broadcast;

#[async_trait]
pub trait PrefabFunctions<Arg: Send + 'static>: Sized {
    type UserLevelInputFunction: Send + 'static;
    async fn on_c2s_channel_received(connect_success: ConnectSuccess, remote: ClientServerRemote, arg: Arg, fx: Self::UserLevelInputFunction) -> Result<(), NetworkError>;
    fn construct(kernel: Box<dyn NetKernel>) -> Self;

    /// Creates a new connection with a central server entailed by the user information
    fn new_connect<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, arg: Arg, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: Self::UserLevelInputFunction) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_connect(username, password, udp_mode, session_security_settings, |connect_success, remote| async move {
            Self::on_c2s_channel_received(connect_success, remote, arg, on_channel_received).await
        });

        Self::construct(Box::new(server_conn_kernel))
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, arg: Arg, on_channel_received: Self::UserLevelInputFunction) -> Self {
        Self::new_connect(username, password, arg, Default::default(), Default::default(), on_channel_received)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, arg: Arg, server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: Self::UserLevelInputFunction) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_register(full_name, username, password, server_addr, udp_mode, session_security_settings, |connect_success, remote| async move {
            Self::on_c2s_channel_received(connect_success, remote, arg, on_channel_received).await
        });

        Self::construct(Box::new(server_conn_kernel))
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, arg: Arg, server_addr: SocketAddr, on_channel_received: Self::UserLevelInputFunction) -> Self {
        Self::new_register(full_name, username, password, arg, server_addr, Default::default(), Default::default(), on_channel_received)
    }

    /// Creates a new authless connection with custom arguments
    fn new_passwordless(uuid: Uuid, server_addr: SocketAddr, arg: Arg, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: Self::UserLevelInputFunction) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_passwordless(uuid, server_addr, udp_mode, session_security_settings,  |connect_success, remote| async move {
            Self::on_c2s_channel_received(connect_success, remote, arg, on_channel_received).await
        });

        Self::construct(Box::new(server_conn_kernel))
    }

    /// Creates a new authless connection with default arguments
    fn new_passwordless_defaults(uuid: Uuid, server_addr: SocketAddr, arg: Arg, on_channel_received: Self::UserLevelInputFunction) -> Self {
        Self::new_passwordless(uuid, server_addr, arg, Default::default(), Default::default(), on_channel_received)
    }
}