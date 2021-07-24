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
        self.writable().await?;
        self.try_write(input).map(|_| ())
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.readable().await?;
        let mut buf = BytesMut::with_capacity(4096);
        let len = self.try_read_buf(&mut buf)?;
        Ok(buf.split_to(len).freeze())
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.peer_addr()
    }
}