use crate::impl_remote;
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
use crate::remote_ext::results::HyperlanPeer;
use crate::remote_ext::ProtocolRemoteExt;

/// A limited version of the [`NodeRemote`] designed to only allow shutdown calls to the protocol
/// as well as several other functions
#[derive(Clone)]
pub struct ClientServerRemote {
    pub(crate) inner: NodeRemote,
    #[allow(dead_code)]
    unprocessed_signals_rx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<NodeResult>>>>,
    conn_type: VirtualTargetType,
}

impl_remote!(ClientServerRemote);

impl ClientServerRemote {
    /// Can only be called once per remote. Allows receiving events
    pub fn get_unprocessed_signals_receiver(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<NodeResult>> {
        self.unprocessed_signals_rx.lock().take()
    }
}

impl TargetLockedRemote for ClientServerRemote {
    fn user(&self) -> &VirtualTargetType {
        &self.conn_type
    }
    fn remote(&mut self) -> &mut NodeRemote {
        &mut self.inner
    }
    fn target_username(&self) -> Option<&String> {
        None
    }
    fn user_mut(&mut self) -> &mut VirtualTargetType {
        &mut self.conn_type
    }
}

impl ClientServerRemote {
    /// Gracefully closes the protocol and kernel executor
    pub async fn shutdown_kernel(mut self) -> Result<(), NetworkError> {
        self.inner.shutdown().await
    }

    pub async fn get_peers(
        &mut self,
        limit: Option<usize>,
    ) -> Result<Vec<HyperlanPeer>, NetworkError> {
        let implicated_cid = self.conn_type.get_implicated_cid();
        self.inner.get_hyperlan_peers(implicated_cid, limit).await
    }
}

pub(self) fn get_socket_addr<T: ToSocketAddrs>(addr: T) -> Result<SocketAddr, NetworkError> {
    addr.to_socket_addrs()
        .map_err(|err| NetworkError::SocketError(err.to_string()))?
        .next()
        .ok_or_else(|| NetworkError::msg("Invalid socket address specified"))
}
