//! WebSocket byte stream adapter for native servers.
//!
//! Wraps `tokio-tungstenite`'s message-oriented `WebSocketStream` into a
//! byte-oriented `AsyncRead + AsyncWrite` stream. This allows the protocol
//! layer to treat WebSocket connections identically to TCP/TLS streams.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_io::tokio::net::TcpStream;
use futures::{Sink, Stream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Byte-oriented wrapper around a WebSocket connection.
///
/// Reads extract binary data from incoming WebSocket frames and buffer it.
/// Writes send binary frames containing the raw bytes.
pub struct WebSocketByteStream {
    inner: WebSocketStream<TcpStream>,
    read_buf: VecDeque<u8>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl WebSocketByteStream {
    pub fn new(
        inner: WebSocketStream<TcpStream>,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            inner,
            read_buf: VecDeque::new(),
            peer_addr,
            local_addr,
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Unpin for WebSocketByteStream {}

impl AsyncRead for WebSocketByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered data first
        if !self.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buf.len());
            let data: Vec<u8> = self.read_buf.drain(..to_read).collect();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        // Poll for next WebSocket message
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                let to_read = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.read_buf.extend(&data[to_read..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Text(text)))) => {
                // Treat text frames as binary data (protocol uses binary framing)
                let data = text.as_bytes();
                let to_read = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.read_buf.extend(&data[to_read..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                Poll::Ready(Ok(())) // EOF
            }
            Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => {
                // Control frames handled automatically by tungstenite; re-poll
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebSocketByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Ensure the sink is ready
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Send as binary WebSocket frame
        let msg = Message::Binary(buf.to_vec().into());
        match Pin::new(&mut self.inner).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::TcpListener;
    use citadel_io::tokio::net::TcpStream as TokioTcpStream;

    use super::*;

    /// Connect a raw TCP client and upgrade to WebSocket, returning
    /// a WebSocketByteStream suitable for testing.
    async fn ws_client_connect(addr: SocketAddr) -> WebSocketByteStream {
        let tcp = TokioTcpStream::connect(addr).await.unwrap();
        let local = tcp.local_addr().unwrap();
        let (ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}"), tcp)
            .await
            .unwrap();
        WebSocketByteStream::new(ws, addr, local)
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        citadel_io::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Validate that WebSocketByteStream round-trips raw bytes.
    #[test]
    fn websocket_byte_stream_round_trip() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = citadel_io::tokio::spawn(async move {
                let (tcp, peer) = listener.accept().await.unwrap();
                let local = tcp.local_addr().unwrap();
                let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let mut stream = WebSocketByteStream::new(ws, peer, local);

                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");

                stream.write_all(b"world").await.unwrap();
                stream.flush().await.unwrap();
            });

            let mut client = ws_client_connect(addr).await;

            client.write_all(b"hello").await.unwrap();
            client.flush().await.unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world");

            server.await.unwrap();
        });
    }

    /// Validate that LengthDelimitedCodec framing works over WebSocketByteStream.
    /// This is the exact framing the Citadel protocol layer uses.
    #[test]
    fn websocket_length_delimited_framing() {
        run(async {
            use bytes::Bytes;
            use citadel_io::tokio_util::codec::LengthDelimitedCodec;
            use futures::{SinkExt, StreamExt};

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = citadel_io::tokio::spawn(async move {
                let (tcp, peer) = listener.accept().await.unwrap();
                let local = tcp.local_addr().unwrap();
                let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let stream = WebSocketByteStream::new(ws, peer, local);

                let mut framed = LengthDelimitedCodec::builder()
                    .length_field_offset(0)
                    .max_frame_length(1024 * 1024 * 64)
                    .length_field_type::<u32>()
                    .length_adjustment(0)
                    .new_framed(stream);

                let packet = framed.next().await.unwrap().unwrap();
                assert_eq!(packet.as_ref(), b"protocol-packet-data");

                framed
                    .send(Bytes::from_static(b"server-response-data"))
                    .await
                    .unwrap();
            });

            let client = ws_client_connect(addr).await;

            let mut framed = LengthDelimitedCodec::builder()
                .length_field_offset(0)
                .max_frame_length(1024 * 1024 * 64)
                .length_field_type::<u32>()
                .length_adjustment(0)
                .new_framed(client);

            framed
                .send(Bytes::from_static(b"protocol-packet-data"))
                .await
                .unwrap();

            let response = framed.next().await.unwrap().unwrap();
            assert_eq!(response.as_ref(), b"server-response-data");

            server.await.unwrap();
        });
    }

    /// Validate large payloads are handled correctly.
    #[test]
    fn websocket_large_payload() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 256) as u8).collect();
            let payload_clone = payload.clone();

            let server = citadel_io::tokio::spawn(async move {
                let (tcp, peer) = listener.accept().await.unwrap();
                let local = tcp.local_addr().unwrap();
                let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let mut stream = WebSocketByteStream::new(ws, peer, local);

                let mut received = vec![0u8; payload_clone.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload_clone);
            });

            let mut client = ws_client_connect(addr).await;

            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();

            server.await.unwrap();
        });
    }
}
