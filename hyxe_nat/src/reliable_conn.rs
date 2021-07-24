use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::net::TcpStream;
use std::net::SocketAddr;

#[async_trait]
/// This represents a direct client to server or client->server->peer connection (usually just TCP) for establishing the hole-punching process
pub trait ReliableOrderedConnectionToTarget: Send {
    /// Accepts plaintext from the NAT traversal driver. Encryption can be optionally applied
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()>;
    /// returns the plaintext
    async fn recv(&self) -> std::io::Result<Bytes>;
    /// Returns the bind addr. Used for establishing a local UDP socket
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Returns the peer addr
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
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
        self.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.peer_addr()
    }
}