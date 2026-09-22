//! The byte stream under a native WebSocket: TCP, or TLS for a `wss://` client.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_io::tokio::net::TcpStream;
use citadel_wire::exports::tokio_rustls::client::TlsStream;

/// The byte stream a WebSocket runs over.
pub enum WsTransport {
    /// TCP: the server's WebSocket listener, and `ws://` clients.
    Plain(TcpStream),
    /// TLS to the server's edge: `wss://` clients.
    ClientTls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for WsTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::ClientTls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WsTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::ClientTls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::ClientTls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::ClientTls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
