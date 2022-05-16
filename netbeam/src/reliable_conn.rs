use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[async_trait]
/// This represents a direct client to server or client->server->peer connection (usually just TCP) for establishing the hole-punching process
pub trait ReliableOrderedStreamToTarget: Send + Sync {
    /// Accepts plaintext from the NAT traversal driver. Encryption can be optionally applied
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()>;
    /// returns the plaintext
    async fn recv(&self) -> std::io::Result<Bytes>;
}

pub trait ConnAddr {
    /// Returns the bind addr. Used for establishing a local UDP socket
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Returns the peer addr. If relaying is used to get the packet to the peer, then the peer addr should be used, not the relay addr
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

pub trait ReliableOrderedConnectionToTarget: ConnAddr + ReliableOrderedStreamToTarget {}
impl<T: ConnAddr + ReliableOrderedStreamToTarget> ReliableOrderedConnectionToTarget for T {}

#[async_trait]
pub trait ReliableOrderedStreamToTargetExt: ReliableOrderedStreamToTarget {
    async fn recv_serialized<T: DeserializeOwned + Send + Sync>(&self) -> std::io::Result<T> {
        let packet = &self.recv().await?;
        Ok(bincode2::deserialize(packet).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?)
    }

    /// Waits until a valid packet gets received, discarding any invalid packets packet
    async fn recv_until_serialized<T: DeserializeOwned + Send + Sync, F: Fn(&T) -> bool + Send>(&self, f: F) -> std::io::Result<T> {
        loop {
            match self.recv_serialized().await {
                Ok(packet) => {
                    if (f)(&packet) {
                        return Ok(packet)
                    }
                }

                Err(err) => {
                    log::warn!("Invalid packet type ... {:?})", err);
                }
            }
        }
    }

    async fn send_serialized<T: Serialize + Send + Sync>(&self, t: T) -> std::io::Result<()> {
        let packet = &bincode2::serialize(&t).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        self.send_to_peer(packet).await
    }
}

impl<T: ReliableOrderedStreamToTarget> ReliableOrderedStreamToTargetExt for T {}

#[async_trait]
impl ReliableOrderedStreamToTarget for TcpStream {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        loop {
            self.writable().await?;

            match self.try_write(input) {
                Ok(_) => {
                    return Ok(())
                }
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
                Ok(0) => {
                    return Ok(Bytes::new())
                },

                Ok(len) => {
                    return Ok(buf.split_to(len).freeze())
                }
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

impl ConnAddr for TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
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
    inner: Mutex<T>
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> From<T> for StreamWrapper<T> {
    fn from(this: T) -> Self {
        StreamWrapper { inner: Mutex::new(this) }
    }
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ReliableOrderedStreamToTarget for StreamWrapper<T> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        self.inner.lock().await.write_all(input).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        let mut buf = BytesMut::with_capacity(4096);
        self.inner.lock().await.read_buf(&mut buf).await.map(|r| buf.split_to(r).freeze())
    }
}

pub mod simulator {
    use bytes::Bytes;
    use async_trait::async_trait;
    use rand::Rng;
    use std::sync::Arc;
    use tokio::sync::mpsc::UnboundedSender;
    use crate::reliable_conn::{ReliableOrderedConnectionToTarget, ConnAddr, ReliableOrderedStreamToTarget};
    use std::net::SocketAddr;

    pub struct NetworkConnSimulator<T> {
        inner: Arc<T>,
        fwd: UnboundedSender<Vec<u8>>
    }

    impl<T: ReliableOrderedConnectionToTarget + 'static> NetworkConnSimulator<T> {
        pub(crate) fn new(min_lag: usize, inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner_fwd = inner.clone();
            let (fwd, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

            tokio::task::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if min_lag != 0 {
                        let rnd = {
                            let mut rng = rand::thread_rng();
                            let max = 2*min_lag;
                            rng.gen_range(min_lag..max) // 50 -> 150ms ping
                        };

                        tokio::time::sleep(std::time::Duration::from_millis(rnd as u64)).await;
                    }

                    inner_fwd.send_to_peer(&packet).await.unwrap();
                }
            });

            Self { inner, fwd }
        }
    }

    #[async_trait]
    impl<T: ReliableOrderedStreamToTarget + 'static> ReliableOrderedStreamToTarget for NetworkConnSimulator<T> {
        async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
            let heap = input.to_vec();
            self.fwd.send(heap).map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
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