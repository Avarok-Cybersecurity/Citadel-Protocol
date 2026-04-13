//! TCP implementations for standard targets

use async_trait::async_trait;
use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use crate::error::{NexusError, NexusResult};
use crate::traits::{ListenerStats, NetworkListener, NetworkStream, SecurityInfo, StreamStats};

/// TCP stream wrapper for the standard implementation
pub struct StdTcpStream {
    inner: citadel_io::tokio::net::TcpStream,
    stats: StreamStatsImpl,
}

impl StdTcpStream {
    pub fn new(stream: citadel_io::tokio::net::TcpStream) -> Self {
        Self {
            inner: stream,
            stats: StreamStatsImpl::new(),
        }
    }
}

impl From<StdTcpStream> for citadel_io::tokio::net::TcpStream {
    fn from(stream: StdTcpStream) -> Self {
        stream.inner
    }
}

impl AsyncRead for StdTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before_len = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let bytes_read = buf.filled().len() - before_len;
            self.stats.bytes_received += bytes_read as u64;
        }

        result
    }
}

impl AsyncWrite for StdTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(bytes_written)) = &result {
            self.stats.bytes_sent += *bytes_written as u64;
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl NetworkStream for StdTcpStream {
    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.local_addr().map_err(NexusError::from)
    }

    fn peer_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.peer_addr().map_err(NexusError::from)
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        use citadel_io::tokio::io::AsyncWriteExt;
        self.inner.shutdown().await.map_err(NexusError::from)
    }

    fn stats(&self) -> StreamStats {
        StreamStats {
            bytes_sent: self.stats.bytes_sent,
            bytes_received: self.stats.bytes_received,
            duration: self.stats.created_at.elapsed(),
            rtt: None, // TCP doesn't expose RTT easily
        }
    }

    fn is_secure(&self) -> bool {
        false
    }

    fn security_info(&self) -> Option<SecurityInfo> {
        None
    }
}

/// TCP listener wrapper for the standard implementation
pub struct StdTcpListener {
    inner: citadel_io::tokio::net::TcpListener,
    stats: ListenerStatsImpl,
}

impl StdTcpListener {
    pub fn new(listener: citadel_io::tokio::net::TcpListener) -> Self {
        Self {
            inner: listener,
            stats: ListenerStatsImpl::new(),
        }
    }
}

impl From<StdTcpListener> for citadel_io::tokio::net::TcpListener {
    fn from(listener: StdTcpListener) -> Self {
        listener.inner
    }
}

#[async_trait]
impl NetworkListener for StdTcpListener {
    type Stream = StdTcpStream;

    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)> {
        match self.inner.accept().await {
            Ok((stream, addr)) => {
                self.stats.connections_accepted += 1;
                self.stats.active_connections += 1;
                Ok((StdTcpStream::new(stream), addr))
            }
            Err(e) => {
                self.stats.connection_errors += 1;
                Err(NexusError::from(e))
            }
        }
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.local_addr().map_err(NexusError::from)
    }

    fn stats(&self) -> ListenerStats {
        ListenerStats {
            connections_accepted: self.stats.connections_accepted,
            active_connections: self.stats.active_connections,
            connection_errors: self.stats.connection_errors,
            uptime: self.stats.created_at.elapsed(),
        }
    }

    fn is_secure(&self) -> bool {
        false
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        // TCP listeners don't have explicit shutdown
        Ok(())
    }
}

/// Internal stats implementation for streams
#[derive(Debug)]
struct StreamStatsImpl {
    bytes_sent: u64,
    bytes_received: u64,
    created_at: Instant,
}

impl StreamStatsImpl {
    fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            created_at: Instant::now(),
        }
    }
}

/// Internal stats implementation for listeners
#[derive(Debug)]
struct ListenerStatsImpl {
    connections_accepted: u64,
    active_connections: u32,
    connection_errors: u64,
    created_at: Instant,
}

impl ListenerStatsImpl {
    fn new() -> Self {
        Self {
            connections_accepted: 0,
            active_connections: 0,
            connection_errors: 0,
            created_at: Instant::now(),
        }
    }
}
