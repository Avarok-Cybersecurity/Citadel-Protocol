//! # Reliable Connection Module
//!
//! This module provides traits and implementations for reliable, ordered network connections.
//! It is designed to support both direct client-server connections and peer-to-peer connections
//! through NAT traversal.
//!
//! ## Key Components
//!
//! - `ReliableOrderedStreamToTarget`: Core trait for reliable message delivery
//! - `ConnAddr`: Trait for connection addressing
//! - `ReliableOrderedConnectionToTarget`: Combined trait for reliable addressed connections
//! - `StreamWrapper`: Implementation for AsyncRead + AsyncWrite streams
//! - `NetworkConnSimulator`: Network condition simulator for testing
//!
//! ## Features
//!
//! - Guaranteed message ordering
//! - Support for NAT traversal
//! - Optional encryption layer
//! - Automatic serialization/deserialization
//! - Network simulation for testing
//!
//! ## Example
//!
//! ```rust,no_run
//! use netbeam::reliable_conn::{ReliableOrderedStreamToTarget, StreamWrapper};
//! use anyhow::Result;
//! use citadel_io::tokio::net::TcpStream;
//!
//! async fn example() -> Result<()> {
//!     // This is just an example - replace with your actual connection
//!     let stream = TcpStream::connect("127.0.0.1:8080").await?;
//!     let mut reliable_stream = StreamWrapper::from(stream);
//!     
//!     // Send data with guaranteed ordering
//!     reliable_stream.send_to_peer(b"Hello").await?;
//!
//!     // Receive response
//!     let response = reliable_stream.recv().await?;
//!     println!("Received: {:?}", response);
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use citadel_io::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use citadel_io::tokio::sync::Mutex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

#[async_trait]
/// Core trait for reliable, ordered message delivery between network endpoints.
///
/// This trait represents a connection that guarantees message ordering and delivery,
/// typically implemented over TCP or similar reliable protocols. It can be used for
/// both direct connections and NAT-traversed peer-to-peer connections.
pub trait ReliableOrderedStreamToTarget: Send + Sync {
    /// Sends plaintext data to the peer.
    ///
    /// This method accepts raw bytes and handles reliable delivery to the target.
    /// Implementations may optionally apply encryption or other transformations.
    ///
    /// # Arguments
    ///
    /// * `input` - The data to send
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()>;

    /// Receives plaintext data from the peer.
    ///
    /// Returns the next message in the ordered sequence from the peer.
    /// Any encryption or transformation is handled by the implementation.
    async fn recv(&self) -> std::io::Result<Bytes>;
}

/// Trait for accessing connection addresses.
///
/// This trait provides methods to get both local and peer socket addresses,
/// which is essential for NAT traversal and connection management.
pub trait ConnAddr {
    /// Returns the local bind address.
    ///
    /// This is typically used for establishing local UDP sockets and
    /// identifying the local endpoint.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    /// Returns the peer's address.
    ///
    /// For direct connections, this is the peer's socket address.
    /// For relayed connections, this should be the ultimate peer address,
    /// not the relay server address.
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

/// Combined trait for reliable, ordered, addressed connections.
///
/// This trait combines `ConnAddr` and `ReliableOrderedStreamToTarget` to provide
/// a complete interface for reliable network connections with addressing capabilities.
pub trait ReliableOrderedConnectionToTarget: ConnAddr + ReliableOrderedStreamToTarget {}
impl<T: ConnAddr + ReliableOrderedStreamToTarget> ReliableOrderedConnectionToTarget for T {}

#[async_trait]
pub trait ReliableOrderedStreamToTargetExt: ReliableOrderedStreamToTarget {
    async fn recv_serialized<T: DeserializeOwned + Send + Sync>(&self) -> std::io::Result<T> {
        let packet = &self.recv().await?;
        Ok(bincode::deserialize(packet)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?)
    }

    /// Waits until a valid packet gets received, discarding any invalid packets packet
    async fn recv_until_serialized<T: DeserializeOwned + Send + Sync, F: Fn(&T) -> bool + Send>(
        &self,
        f: F,
    ) -> std::io::Result<T> {
        loop {
            match self.recv_serialized().await {
                Ok(packet) => {
                    if (f)(&packet) {
                        return Ok(packet);
                    }
                }

                Err(err) => {
                    log::warn!(target: "citadel", "Invalid packet type ... {err:?})");
                }
            }
        }
    }

    async fn send_serialized<T: Serialize + Send + Sync>(&self, t: T) -> std::io::Result<()> {
        let packet = &bincode::serialize(&t)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        self.send_to_peer(packet).await
    }
}

impl<T: ReliableOrderedStreamToTarget> ReliableOrderedStreamToTargetExt for T {}

#[async_trait]
#[cfg(not(target_family = "wasm"))]
impl ReliableOrderedStreamToTarget for citadel_io::tokio::net::TcpStream {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        loop {
            self.writable().await?;

            match self.try_write(input) {
                Ok(_) => return Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            self.readable().await?;

            match self.try_read_buf(&mut buf) {
                Ok(0) => return Ok(Bytes::new()),

                Ok(len) => return Ok(buf.split_to(len).freeze()),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl ConnAddr for citadel_io::tokio::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        citadel_io::tokio::net::TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        citadel_io::tokio::net::TcpStream::peer_addr(self)
    }
}

#[async_trait]
impl<T: ReliableOrderedStreamToTarget + ?Sized> ReliableOrderedStreamToTarget for Arc<T> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        T::send_to_peer(self, input).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        T::recv(self).await
    }
}

pub struct StreamWrapper<T> {
    inner: Mutex<T>,
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> From<T> for StreamWrapper<T> {
    fn from(this: T) -> Self {
        StreamWrapper {
            inner: Mutex::new(this),
        }
    }
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ReliableOrderedStreamToTarget for StreamWrapper<T> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        self.inner.lock().await.write_all(input).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        let mut buf = BytesMut::with_capacity(4096);
        self.inner
            .lock()
            .await
            .read_buf(&mut buf)
            .await
            .map(|r| buf.split_to(r).freeze())
    }
}

pub mod simulator {
    //! Network condition simulation module.
    //!
    //! This module provides tools for simulating various network conditions
    //! such as latency and packet loss, which is useful for testing network
    //! applications under different scenarios.

    use crate::reliable_conn::{
        ConnAddr, ReliableOrderedConnectionToTarget, ReliableOrderedStreamToTarget,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use citadel_io::tokio::sync::mpsc::UnboundedSender;
    use rand::Rng;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// Simulates network conditions for testing.
    ///
    /// This struct wraps a reliable connection and adds simulated network
    /// conditions such as latency, making it useful for testing how
    /// applications behave under various network scenarios.
    pub struct NetworkConnSimulator<T> {
        inner: Arc<T>,
        fwd: UnboundedSender<Vec<u8>>,
    }

    impl<T: ReliableOrderedConnectionToTarget + 'static> NetworkConnSimulator<T> {
        #[cfg_attr(target_family = "wasm", allow(dead_code))]
        pub(crate) fn new(min_lag: usize, inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner_fwd = inner.clone();
            let (fwd, mut rx) = citadel_io::tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

            citadel_io::tokio::task::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if min_lag != 0 {
                        let rnd = {
                            let mut rng = rand::thread_rng();
                            let max = 2 * min_lag;
                            rng.gen_range(min_lag..max) // 50 -> 150ms ping
                        };

                        citadel_io::tokio::time::sleep(std::time::Duration::from_millis(
                            rnd as u64,
                        ))
                        .await;
                    }

                    inner_fwd.send_to_peer(&packet).await.unwrap();
                }
            });

            Self { inner, fwd }
        }
    }

    #[async_trait]
    impl<T: ReliableOrderedStreamToTarget + 'static> ReliableOrderedStreamToTarget
        for NetworkConnSimulator<T>
    {
        async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
            let heap = input.to_vec();
            self.fwd
                .send(heap)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
        }

        async fn recv(&self) -> std::io::Result<Bytes> {
            self.inner.recv().await
        }
    }

    impl<T: ReliableOrderedConnectionToTarget + 'static> ConnAddr for NetworkConnSimulator<T> {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
    }
}
