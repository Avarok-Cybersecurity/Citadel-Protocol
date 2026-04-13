//! Network stream abstractions

use crate::error::NexusResult;
use async_trait::async_trait;
#[cfg(not(target_family = "wasm"))]
use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(target_family = "wasm")]
use futures::io::{AsyncRead, AsyncWrite};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Trait for network streams providing bidirectional communication
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait NetworkStream: AsyncRead + AsyncWrite + Unpin + 'static {
    /// Get the local address of this stream
    fn local_addr(&self) -> NexusResult<SocketAddr>;

    /// Get the remote/peer address of this stream
    fn peer_addr(&self) -> NexusResult<SocketAddr>;

    /// Attempt to shutdown the write half of the stream gracefully
    async fn shutdown(&mut self) -> NexusResult<()>;

    /// Get stream statistics (bytes sent/received, etc.)
    fn stats(&self) -> StreamStats;

    /// Check if the stream supports secure transport
    fn is_secure(&self) -> bool;

    /// Get security information if this is a secure stream
    fn security_info(&self) -> Option<SecurityInfo>;
}

/// Statistics about a network stream
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Connection duration
    pub duration: std::time::Duration,

    /// Current round-trip time (if available)
    pub rtt: Option<std::time::Duration>,
}

/// Security information for secure streams
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Protocol used (TLS, DTLS, etc.)
    pub protocol: String,

    /// Cipher suite
    pub cipher_suite: Option<String>,

    /// Certificate information
    pub peer_certificate: Option<Vec<u8>>,
}

/// Trait for accepting incoming stream connections
#[async_trait]
pub trait StreamAcceptor: Send + Sync + 'static {
    /// The type of stream this acceptor produces
    type Stream: NetworkStream;

    /// Accept the next incoming connection
    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)>;
}

/// Wrapper for unified stream operations across platforms
pub struct UnifiedStream<S: NetworkStream> {
    inner: S,
}

impl<S: NetworkStream> UnifiedStream<S> {
    pub fn new(stream: S) -> Self {
        Self { inner: stream }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: NetworkStream> AsyncRead for UnifiedStream<S> {
    #[cfg(not(target_family = "wasm"))]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    #[cfg(target_family = "wasm")]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: NetworkStream> AsyncWrite for UnifiedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    #[cfg(not(target_family = "wasm"))]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    #[cfg(target_family = "wasm")]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<S: NetworkStream + Send> NetworkStream for UnifiedStream<S> {
    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.peer_addr()
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        self.inner.shutdown().await
    }

    fn stats(&self) -> StreamStats {
        self.inner.stats()
    }

    fn is_secure(&self) -> bool {
        self.inner.is_secure()
    }

    fn security_info(&self) -> Option<SecurityInfo> {
        self.inner.security_info()
    }
}
