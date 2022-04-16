use std::marker::PhantomData;
use crate::prelude::{NodeRemote, SessionSecuritySettings, UdpMode, NetworkError, SecBuffer, NetKernel, ConnectSuccess, HdpServerResult};
use crate::prefabs::client::single_connection::{ConnectionType, SingleClientServerConnectionKernel};
use parking_lot::Mutex;
use crate::prelude::results::PeerConnectSuccess;
use std::collections::HashMap;
use futures::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use crate::prefabs::ClientServerRemote;
use async_trait::async_trait;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
///
/// After establishing a connection to the central node, this kernel then begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<F, Fut> {
    inner_kernel: Box<dyn NetKernel>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> (F, Fut)>
}

#[async_trait]
impl NetKernel for PeerConnectionKernel<F, Fut> {
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(server_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        self.inner_kernel.on_node_event_received(message).await
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        self.inner_kernel.on_stop().await
    }
}

pub enum PeerID {
    CID(u64),
    Username(String)
}

pub struct PeerIDAggregator {
    inner: Vec<PeerID>
}

impl PeerIDAggregator {
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn add<T: Into<PeerID>>(mut self, peer: T) -> Self {
        self.inner.push(peer.into());
        self
    }

    pub fn finish(self) -> Vec<PeerID> {
        self.inner
    }
}

impl From<String> for PeerID {
    fn from(val: String) -> Self {
        Self::Username(val.into())
    }
}

impl From<u64> for PeerID {
    fn from(cid: u64) -> Self {
        PeerID::CID(cid)
    }
}

impl<F, Fut> PeerConnectionKernel<F, Fut>
    where
        F: FnOnce(HashMap<u64, PeerConnectSuccess>) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    /// Creates a new connection with a central server entailed by the user information
    pub fn new_connect<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, peers: Vec<PeerID>, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_connect(username, password, udp_mode, session_security_settings, |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    pub fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, peers: Vec<PeerID>, on_channel_received: F) -> Self {
        Self::new_connect(username, password, peers, Default::default(), Default::default(), on_channel_received)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    pub fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, peers: Vec<PeerID>, server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_register(full_name, username, password, server_addr, udp_mode, session_security_settings, |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    pub fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, peers: Vec<PeerID>, server_addr: SocketAddr, on_channel_received: F) -> Self {
        Self::new_register(full_name, username, password, peers, server_addr, Default::default(), Default::default(), on_channel_received)
    }

    /// Creates a new authless connection with custom arguments
    pub fn new_passwordless(server_addr: SocketAddr, peers: Vec<PeerID>, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_passwordless(server_addr, udp_mode, session_security_settings,  |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// Creates a new authless connection with default arguments
    pub fn new_passwordless_defaults(server_addr: SocketAddr, peers: Vec<PeerID>, on_channel_received: F) -> Self {
        Self::new_passwordless(server_addr, peers, Default::default(), Default::default(), on_channel_received)
    }
}

async fn on_server_connect_success<F, Fut>(connect_success: ConnectSuccess, remote: ClientServerRemote, f: F, peers: Vec<PeerID>) -> Result<(), NetworkError>
    where F: FnOnce(HashMap<u64, PeerConnectSuccess>) -> Fut + Send + 'static,
          Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    // TODO: connect to peers, then, execute 'f'
    Ok(())
}