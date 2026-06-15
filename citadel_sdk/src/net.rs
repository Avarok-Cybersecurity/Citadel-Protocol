//! Browser-to-browser serverless connections.
//!
//! Provides a socket-like API for connecting two browser peers directly
//! without a central server. Role negotiation (which peer acts as server vs
//! client) is handled automatically via the signaling layer.
//!
//! # Usage
//!
//! Both browser peers run identical code — role assignment is transparent:
//!
//! ```rust,ignore
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::net::BrowserConnection;
//! use futures::StreamExt;
//!
//! let conn = BrowserConnection::new(config).await?;
//! let (tx, mut rx) = conn.split();
//! tx.send_message(SecBuffer::from("hello peer")).await?;
//! while let Some(msg) = rx.next().await {
//!     // post-quantum encrypted message from the other peer
//! }
//! ```

use crate::prefabs::client::serverless::ServerlessKernel;
use crate::prefabs::ClientServerRemote;
use crate::prelude::*;

/// A socket-like connection between two browser peers.
///
/// Created via [`BrowserConnection::new()`]. One peer automatically becomes
/// the server, the other the client — this is transparent to the caller.
/// The connection runs the full Citadel session protocol (post-quantum
/// encryption, ratcheting) over a WebRTC DataChannel.
///
/// # Shutdown
///
/// On drop, the underlying kernel is gracefully shut down via
/// [`NodeRemote::shutdown()`].
pub struct BrowserConnection<R: Ratchet = StackedRatchet> {
    channel: Option<PeerChannel<R>>,
    remote: ClientServerRemote<R>,
    /// Keeps the kernel + protocol machinery alive in the background.
    _kernel_task: citadel_io::tokio::task::JoinHandle<Result<(), NetworkError>>,
}

impl<R: Ratchet> BrowserConnection<R> {
    /// Establish a serverless browser-to-browser connection.
    ///
    /// Both peers call this with the same room token. One is automatically
    /// assigned the server role and the other the client role via the
    /// signaling service. The returned connection is fully established with
    /// post-quantum encrypted channels ready for use.
    pub async fn new(config: ServerlessConfig) -> Result<Self, NetworkError> {
        let (conn_tx, conn_rx) = citadel_io::tokio::sync::oneshot::channel();
        let kernel = ServerlessKernel::<R>::new(conn_tx);

        let node_future = NodeBuilder::<R, DefaultTransport>::default()
            .with_no_central_server(config)
            .with_backend(BackendType::InMemory)
            .build(kernel)?;

        let kernel_task =
            citadel_io::tokio::task::spawn_local(async move { node_future.await.map(|_| ()) });

        let connection = match conn_rx.await {
            Ok(conn) => conn,
            Err(_) => {
                kernel_task.abort();
                return Err(NetworkError::internal(
                    "Kernel stopped before connection established",
                ));
            }
        };

        Ok(Self {
            channel: connection.channel,
            remote: connection.remote,
            _kernel_task: kernel_task,
        })
    }

    /// Split into independent send/receive halves (like `TcpStream::into_split`).
    ///
    /// # Panics
    ///
    /// Panics if the channel has already been taken via [`Self::take_channel`].
    pub fn split(mut self) -> (PeerChannelSendHalf<R>, PeerChannelRecvHalf<R>) {
        self.channel.take().expect("Channel already taken").split()
    }

    /// Take the underlying [`PeerChannel`] for full protocol-level control.
    pub fn take_channel(&mut self) -> Option<PeerChannel<R>> {
        self.channel.take()
    }

    /// Reference to the remote for control operations (disconnect, etc.).
    pub fn remote(&self) -> &ClientServerRemote<R> {
        &self.remote
    }
}

impl<R: Ratchet> Drop for BrowserConnection<R> {
    fn drop(&mut self) {
        let remote = self.remote.inner.clone();
        drop(citadel_io::tokio::task::spawn_local(async move {
            let _ = remote.shutdown().await;
        }));
    }
}
