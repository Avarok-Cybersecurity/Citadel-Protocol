//! Pre-built Network Components
//!
//! This module provides a collection of pre-built network components for both client
//! and server implementations in the Citadel Protocol. These components offer ready-to-use
//! functionality for common networking patterns and use cases.
//!
//! # Features
//! - Client-side networking components
//! - Server-side networking components
//! - Remote connection management
//! - File transfer handling
//! - Signal and event processing
//! - Connection security management
//! - Peer discovery and listing
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
//!
//! # fn main() -> Result<(), NetworkError> {
//!#  async fn connect_to_server() -> Result<(), NetworkError> {
//!     let settings = DefaultServerConnectionSettingsBuilder::transient("127.0.0.1:25021")
//!         .with_udp_mode(UdpMode::Enabled)
//!         .build()?;
//!
//!     let kernel = SingleClientServerConnectionKernel::new(
//!         settings,
//!         |conn| async move {
//!             println!("Connected to server!");
//!             Ok(())
//!         },
//!     );
//!
//!     let client = DefaultNodeBuilder::default().build(kernel)?;
//!
//!     let _result = client.await?;
//!     Ok(())
//! # }
//! # Ok::<(), NetworkError>(())
//! }
//!
//! ```
//!
//! # Important Notes
//! - File transfer handlers can only be obtained once
//! - Signal receivers are single-use
//! - Remote shutdown is graceful and asynchronous
//! - Connection types determine available operations
//!
//! # Related Components
//! - [`client`]: Client-side networking implementations
//! - [`server`]: Server-side networking implementations
//!
//! [`client`]: crate::prefabs::client
//! [`server`]: crate::prefabs::server

use crate::impl_remote;
use crate::prefabs::client::peer_connection::FileTransferHandleRx;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_io::Mutex;
use citadel_proto::prelude::*;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Kernels for clients
pub mod client;
/// Kernels for servers
pub mod server;
/// Shared utilities between client and server kernels
pub mod shared;
use crate::prelude::user_ids::TargetLockedRemote;
use crate::remote_ext::results::LocalGroupPeer;
use crate::remote_ext::ProtocolRemoteExt;

/// A limited version of the [`NodeRemote`] designed to only allow shutdown calls to the protocol
/// as well as several other functions
#[derive(Clone)]
pub struct ClientServerRemote<R: Ratchet> {
    pub(crate) inner: NodeRemote<R>,
    pub(crate) unprocessed_signals_rx: Arc<Mutex<Option<UnboundedReceiver<NodeResult<R>>>>>,
    pub(crate) file_transfer_handle_rx: Arc<Mutex<Option<FileTransferHandleRx>>>,
    conn_type: VirtualTargetType,
    session_security_settings: SessionSecuritySettings,
}

impl<R: Ratchet> Deref for ClientServerRemote<R> {
    type Target = NodeRemote<R>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<R: Ratchet> DerefMut for ClientServerRemote<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl_remote!(ClientServerRemote);

impl<R: Ratchet> ClientServerRemote<R> {
    /// constructs a new [`ClientServerRemote`] from a [`ClientServerRemote`] and a [`VirtualTargetType`]
    pub fn new(
        conn_type: VirtualTargetType,
        remote: NodeRemote<R>,
        session_security_settings: SessionSecuritySettings,
        unprocessed_signals_rx: Option<UnboundedReceiver<NodeResult<R>>>,
        file_transfer_handle_rx: Option<FileTransferHandleRx>,
    ) -> Self {
        // TODO: Add handles, only the server calls this
        Self {
            inner: remote,
            unprocessed_signals_rx: Arc::new(Mutex::new(unprocessed_signals_rx)),
            file_transfer_handle_rx: Arc::new(Mutex::new(file_transfer_handle_rx)),
            conn_type,
            session_security_settings,
        }
    }
    /// Can only be called once per remote. Allows receiving events
    pub fn get_unprocessed_signals_receiver(
        &self,
    ) -> Option<citadel_io::tokio::sync::mpsc::UnboundedReceiver<NodeResult<R>>> {
        self.unprocessed_signals_rx.lock().take()
    }

    /// Obtains a receiver which yields incoming file/object transfer handles
    pub fn get_incoming_file_transfer_handle(&self) -> Result<FileTransferHandleRx, NetworkError> {
        self.file_transfer_handle_rx
            .lock()
            .take()
            .ok_or(NetworkError::InternalError(
                "This function has already been called",
            ))
    }
}

impl<R: Ratchet> TargetLockedRemote<R> for ClientServerRemote<R> {
    fn user(&self) -> &VirtualTargetType {
        &self.conn_type
    }
    fn remote(&self) -> &NodeRemote<R> {
        &self.inner
    }
    fn target_username(&self) -> Option<&str> {
        None
    }
    fn user_mut(&mut self) -> &mut VirtualTargetType {
        &mut self.conn_type
    }

    fn session_security_settings(&self) -> Option<&SessionSecuritySettings> {
        Some(&self.session_security_settings)
    }
}

impl<R: Ratchet> ClientServerRemote<R> {
    /// Gracefully closes the protocol and kernel executor
    pub async fn shutdown_kernel(&self) -> Result<(), NetworkError> {
        self.inner.shutdown().await
    }

    pub async fn get_peers(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<LocalGroupPeer>, NetworkError> {
        let session_cid = self.conn_type.get_session_cid();
        let peer_info = self.inner.get_local_group_peers(session_cid, limit).await?;
        Ok(peer_info
            .iter()
            .map(|info| LocalGroupPeer {
                cid: info.cid,
                is_online: info.is_online,
            })
            .collect())
    }
}

pub fn get_socket_addr<T: ToSocketAddrs>(addr: T) -> Result<SocketAddr, NetworkError> {
    addr.to_socket_addrs()
        .map_err(|err| NetworkError::SocketError(err.to_string()))?
        .next()
        .ok_or_else(|| NetworkError::msg("Invalid socket address specified"))
}
