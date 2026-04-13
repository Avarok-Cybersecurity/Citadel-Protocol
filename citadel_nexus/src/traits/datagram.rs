//! Datagram socket abstractions

use crate::error::NexusResult;
use async_trait::async_trait;
use serde::Serialize;
use std::net::SocketAddr;

/// Trait for UDP-like datagram sockets
///
/// This trait abstracts over different types of unreliable datagram transports
/// such as UDP sockets, WebRTC unreliable DataChannels, or other packet-based protocols.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait DatagramSocket: 'static {
    /// Send a datagram to the specified address
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> NexusResult<usize>;

    /// Receive a datagram, returning the data and sender address
    async fn recv_from(&self, buf: &mut [u8]) -> NexusResult<(usize, SocketAddr)>;

    /// Get the local address this socket is bound to
    fn local_addr(&self) -> NexusResult<SocketAddr>;

    /// Connect to a specific remote address for subsequent sends
    async fn connect(&self, addr: SocketAddr) -> NexusResult<()>;

    /// Send data to the connected address (requires connect() first)
    async fn send(&self, buf: &[u8]) -> NexusResult<usize>;

    /// Receive data from the connected address
    async fn recv(&self, buf: &mut [u8]) -> NexusResult<usize>;

    /// Get socket statistics
    fn stats(&self) -> DatagramStats;

    /// Check if this socket supports multicast
    fn supports_multicast(&self) -> bool;

    /// Join a multicast group
    async fn join_multicast(&self, multicast_addr: SocketAddr) -> NexusResult<()>;

    /// Leave a multicast group
    async fn leave_multicast(&self, multicast_addr: SocketAddr) -> NexusResult<()>;
}

/// Statistics for datagram sockets
#[derive(Debug, Clone, Default)]
pub struct DatagramStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,

    /// Total datagrams received
    pub datagrams_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Send errors
    pub send_errors: u64,

    /// Receive errors
    pub recv_errors: u64,

    /// Maximum datagram size supported
    pub max_datagram_size: usize,
}

/// Extension trait providing convenience methods for datagram operations
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait DatagramExt: DatagramSocket {
    /// Send a message with automatic serialization
    async fn send_message<T>(&self, msg: &T, target: SocketAddr) -> NexusResult<()>
    where
        T: serde::Serialize + Send + Sync,
    {
        let data =
            serde_json::to_vec(msg).map_err(|e| crate::error::NexusError::Other(e.to_string()))?;
        self.send_to(&data, target).await.map(|_| ())
    }

    /// Send structured data as JSON
    async fn send_json<T: Serialize + Sync>(
        &self,
        data: &T,
        target: SocketAddr,
    ) -> NexusResult<()> {
        let data = serde_json::to_vec(data).map_err(|e| {
            crate::error::NexusError::Other(format!("JSON serialization failed: {}", e))
        })?;
        self.send_to(&data, target).await?;
        Ok(())
    }

    /// Receive and deserialize a message
    async fn recv_message<T>(&self) -> NexusResult<(T, SocketAddr)>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut buf = vec![0u8; 65536]; // Standard UDP max size
        let (len, addr) = self.recv_from(&mut buf).await?;
        let msg = serde_json::from_slice(&buf[..len])
            .map_err(|e| crate::error::NexusError::Other(e.to_string()))?;
        Ok((msg, addr))
    }

    /// Send data with retry logic
    async fn send_to_reliable(
        &self,
        buf: &[u8],
        target: SocketAddr,
        max_retries: u32,
    ) -> NexusResult<usize> {
        let mut attempts = 0;
        loop {
            match self.send_to(buf, target).await {
                Ok(size) => return Ok(size),
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_retries {
                        return Err(e);
                    }
                    // Brief delay before retry
                    #[cfg(not(target_family = "wasm"))]
                    citadel_io::tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    #[cfg(target_family = "wasm")]
                    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                        &mut |resolve, _| {
                            web_sys::window()
                                .unwrap()
                                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
                                .unwrap();
                        },
                    ))
                    .await
                    .unwrap();
                }
            }
        }
    }
}

// Blanket implementation for all datagram sockets
impl<T: DatagramSocket> DatagramExt for T {}

/// Configuration for datagram sockets
#[derive(Debug, Clone)]
pub struct DatagramConfig {
    /// Bind address
    pub bind_addr: SocketAddr,

    /// Send buffer size
    pub send_buffer_size: Option<usize>,

    /// Receive buffer size
    pub recv_buffer_size: Option<usize>,

    /// Enable broadcast
    pub broadcast: bool,

    /// TTL for outgoing packets
    pub ttl: Option<u32>,

    /// Type of Service (ToS) field
    pub tos: Option<u8>,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            send_buffer_size: None,
            recv_buffer_size: None,
            broadcast: false,
            ttl: None,
            tos: None,
        }
    }
}
