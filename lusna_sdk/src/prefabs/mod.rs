use hyxe_net::prelude::*;

/// Kernels for servers
pub mod server;
/// Kernels for clients
pub mod client;
use crate::prelude::user_ids::TargetLockedRemote;

/// A limited version of the [`NodeRemote`] designed to only allow shutdown calls to the protocol
/// as well as several other functions
#[derive(Clone)]
pub struct ClientServerRemote {
    pub(crate) inner: NodeRemote,
    conn_type: VirtualTargetType
}

impl TargetLockedRemote for ClientServerRemote {
    fn user(&self) -> &VirtualTargetType {
        &self.conn_type
    }

    fn remote(&mut self) -> &mut NodeRemote {
        &mut self.inner
    }
}

impl ClientServerRemote {
    /// Gracefully closes the protocol and kernel executor
    pub async fn shutdown_kernel(mut self) -> Result<(), NetworkError> {
        self.inner.shutdown().await
    }
}