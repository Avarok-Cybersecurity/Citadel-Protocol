use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[async_trait]
/// This represents a direct client to server or client->server->peer connection (usually just TCP) for establishing the hole-punching process
pub trait ReliableOrderedConnectionToTarget: Send + Sync {
    /// Accepts plaintext from the NAT traversal driver. Encryption can be optionally applied
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()>;
    /// returns the plaintext
    async fn recv(&self) -> std::io::Result<Bytes>;
    /// Returns the bind addr. Used for establishing a local UDP socket
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Returns the peer addr. If relaying is used to get the packet to the peer, then the peer addr should be used, not the relay addr
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;

    async fn recv_serialized<T: DeserializeOwned + Send + Sync>(&self) -> std::io::Result<T> {
        Ok(bincode2::deserialize(&self.recv().await?).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?)
    }

    async fn send_serialized<T: Serialize + Send + Sync>(&self, t: T) -> std::io::Result<()> {
        self.send_to_peer(&bincode2::serialize(&t).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?).await
    }
}

#[async_trait]
impl ReliableOrderedConnectionToTarget for TcpStream {
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
                    return Err(e.into());
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
                    return Err(e.into());
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}


#[async_trait]
impl<T: ReliableOrderedConnectionToTarget> ReliableOrderedConnectionToTarget for &'_ T {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        T::send_to_peer(self, input).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        T::recv(self).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        T::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        T::peer_addr(self)
    }
}

#[async_trait]
impl<T: ReliableOrderedConnectionToTarget> ReliableOrderedConnectionToTarget for Arc<T> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        T::send_to_peer(self, input).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        T::recv(self).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        T::local_addr(self)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        T::peer_addr(self)
    }
}

#[cfg(test)]
pub(crate) mod simulator {
    use crate::reliable_conn::ReliableOrderedConnectionToTarget;
    use std::marker::PhantomData;
    use bytes::Bytes;
    use std::net::SocketAddr;
    use async_trait::async_trait;
    use std::time::Duration;

    pub struct NetworkConnSimulator<'a, T: ReliableOrderedConnectionToTarget + 'a> {
        inner: T,
        _pd: PhantomData<&'a T>
    }

    impl<T: ReliableOrderedConnectionToTarget> From<T> for NetworkConnSimulator<'_, T> {
        fn from(inner: T) -> Self {
            Self { inner, _pd: Default::default() }
        }
    }

    #[async_trait]
    impl<T: ReliableOrderedConnectionToTarget> ReliableOrderedConnectionToTarget for NetworkConnSimulator<'_, T> {
        async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
            self.inner.send_to_peer(input).await?;
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(())
        }

        async fn recv(&self) -> std::io::Result<Bytes> {
            self.inner.recv().await
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
    }
}