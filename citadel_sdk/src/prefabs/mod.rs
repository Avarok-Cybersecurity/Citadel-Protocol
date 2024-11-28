use crate::impl_remote;
use crate::prefabs::client::peer_connection::FileTransferHandleRx;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_io::Mutex;
use citadel_proto::prelude::*;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// Kernels for clients
pub mod client;
/// Kernels for servers
pub mod server;
pub(crate) mod shared;
use crate::prelude::user_ids::TargetLockedRemote;
use crate::remote_ext::results::LocalGroupPeer;
use crate::remote_ext::ProtocolRemoteExt;

/// A limited version of the [`NodeRemote`] designed to only allow shutdown calls to the protocol
/// as well as several other functions
#[derive(Clone)]
pub struct ClientServerRemote {
    pub(crate) inner: NodeRemote,
    pub(crate) unprocessed_signals_rx: Arc<Mutex<Option<UnboundedReceiver<NodeResult>>>>,
    pub(crate) file_transfer_handle_rx: Arc<Mutex<Option<FileTransferHandleRx>>>,
    conn_type: VirtualTargetType,
    session_security_settings: SessionSecuritySettings,
}

impl_remote!(ClientServerRemote);

impl ClientServerRemote {
    /// constructs a new [`ClientServerRemote`] from a [`NodeRemote`] and a [`VirtualTargetType`]
    pub fn new(
        conn_type: VirtualTargetType,
        remote: NodeRemote,
        session_security_settings: SessionSecuritySettings,
        unprocessed_signals_rx: Option<UnboundedReceiver<NodeResult>>,
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
    ) -> Option<citadel_io::tokio::sync::mpsc::UnboundedReceiver<NodeResult>> {
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

impl TargetLockedRemote for ClientServerRemote {
    fn user(&self) -> &VirtualTargetType {
        &self.conn_type
    }
    fn remote(&self) -> &NodeRemote {
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

impl ClientServerRemote {
    /// Gracefully closes the protocol and kernel executor
    pub async fn shutdown_kernel(self) -> Result<(), NetworkError> {
        self.inner.shutdown().await
    }

    pub async fn get_peers(
        &mut self,
        limit: Option<usize>,
    ) -> Result<Vec<LocalGroupPeer>, NetworkError> {
        let implicated_cid = self.conn_type.get_implicated_cid();
        let peer_info = self
            .inner
            .get_local_group_peers(implicated_cid, limit)
            .await?;
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
