//! UDP implementations for standard targets

use async_trait::async_trait;
//use bytes::BytesMut;
use std::net::SocketAddr;
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{NexusResult, NexusError};
use crate::traits::{DatagramSocket, DatagramStats};

/// UDP socket wrapper for the standard implementation
pub struct StdUdpSocket {
    inner: citadel_io::tokio::net::UdpSocket,
    stats: DatagramStatsImpl,
    connected_addr: std::sync::RwLock<Option<SocketAddr>>,
}

impl StdUdpSocket {
    pub fn new(socket: citadel_io::tokio::net::UdpSocket) -> Self {
        Self {
            inner: socket,
            stats: DatagramStatsImpl::new(),
            connected_addr: std::sync::RwLock::new(None),
        }
    }

    /// Convert back to a Tokio UDP socket
    pub fn into_tokio(self) -> citadel_io::tokio::net::UdpSocket {
        self.inner
    }
    
    /// Create a UDP socket bound to the given address
    pub async fn bind(addr: SocketAddr) -> NexusResult<Self> {
        let socket = citadel_io::tokio::net::UdpSocket::bind(addr).await
            .map_err(NexusError::from)?;
        Ok(Self::new(socket))
    }
}

#[async_trait]
impl DatagramSocket for StdUdpSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> NexusResult<usize> {
        match self.inner.send_to(buf, target).await {
            Ok(bytes_sent) => {
                self.update_send_stats(bytes_sent);
                Ok(bytes_sent)
            }
            Err(e) => {
                self.update_error_stats(true);
                Err(NexusError::from(e))
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> NexusResult<(usize, SocketAddr)> {
        match self.inner.recv_from(buf).await {
            Ok((bytes_received, addr)) => {
                self.update_recv_stats(bytes_received);
                Ok((bytes_received, addr))
            }
            Err(e) => {
                self.update_error_stats(false);
                Err(NexusError::from(e))
            }
        }
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.inner.local_addr().map_err(NexusError::from)
    }

    async fn connect(&self, addr: SocketAddr) -> NexusResult<()> {
        self.inner.connect(addr).await.map_err(NexusError::from)?;
        // Update connected address
        *self.connected_addr.write().unwrap() = Some(addr);
        Ok(())
    }

    async fn send(&self, buf: &[u8]) -> NexusResult<usize> {
        match self.inner.send(buf).await {
            Ok(bytes_sent) => {
                self.update_send_stats(bytes_sent);
                Ok(bytes_sent)
            }
            Err(e) => {
                self.update_error_stats(true);
                Err(NexusError::from(e))
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> NexusResult<usize> {
        match self.inner.recv(buf).await {
            Ok(bytes_received) => {
                self.update_recv_stats(bytes_received);
                Ok(bytes_received)
            }
            Err(e) => {
                self.update_error_stats(false);
                Err(NexusError::from(e))
            }
        }
    }

    fn stats(&self) -> DatagramStats {
        DatagramStats {
            datagrams_sent: self.stats.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            recv_errors: self.stats.recv_errors.load(Ordering::Relaxed),
            max_datagram_size: 65507, // Standard UDP maximum
        }
    }

    fn supports_multicast(&self) -> bool {
        true
    }

    async fn join_multicast(&self, multicast_addr: SocketAddr) -> NexusResult<()> {
        match multicast_addr {
            SocketAddr::V4(addr) => {
                self.inner.join_multicast_v4(*addr.ip(), std::net::Ipv4Addr::UNSPECIFIED)
                    .map_err(NexusError::from)
            }
            SocketAddr::V6(addr) => {
                self.inner.join_multicast_v6(addr.ip(), 0)
                    .map_err(NexusError::from)
            }
        }
    }

    async fn leave_multicast(&self, multicast_addr: SocketAddr) -> NexusResult<()> {
        match multicast_addr {
            SocketAddr::V4(addr) => {
                self.inner.leave_multicast_v4(*addr.ip(), std::net::Ipv4Addr::UNSPECIFIED)
                    .map_err(NexusError::from)
            }
            SocketAddr::V6(addr) => {
                self.inner.leave_multicast_v6(addr.ip(), 0)
                    .map_err(NexusError::from)
            }
        }
    }
}

impl StdUdpSocket {
    fn update_send_stats(&self, bytes_sent: usize) {
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(bytes_sent as u64, Ordering::Relaxed);
    }

    fn update_recv_stats(&self, bytes_received: usize) {
        self.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(bytes_received as u64, Ordering::Relaxed);
    }

    fn update_error_stats(&self, is_send_error: bool) {
        if is_send_error {
            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the raw Tokio UDP socket
    pub fn inner(&self) -> &citadel_io::tokio::net::UdpSocket {
        &self.inner
    }

    /// Set socket options for NAT traversal
    pub fn configure_for_nat_traversal(&self) -> NexusResult<()> {
        // TODO: Implement socket configuration for NAT traversal
        // This would set SO_REUSEADDR, SO_REUSEPORT, etc.
        Ok(())
    }

    /// Bind to a specific address with NAT traversal optimizations
    pub async fn bind_for_nat_traversal(addr: SocketAddr) -> NexusResult<Self> {
        // TODO: Implement socket2-based binding with NAT traversal optimizations
        // For now, use standard binding
        Self::bind(addr).await
    }
}

/// Internal stats implementation for UDP sockets
#[derive(Debug)]
struct DatagramStatsImpl {
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_errors: AtomicU64,
    recv_errors: AtomicU64,
    created_at: Instant,
}

impl DatagramStatsImpl {
    fn new() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }
}