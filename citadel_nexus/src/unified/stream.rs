//! Unified stream implementation for different platform backends

use async_trait::async_trait;
#[cfg(not(target_family = "wasm"))]
use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf, AsyncWriteExt};
#[cfg(target_family = "wasm")]
use futures::io::{AsyncRead, AsyncWrite};
#[cfg(target_family = "wasm")]
use tokio::io::ReadBuf;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use crate::error::{NexusResult, NexusError};
use crate::traits::{NetworkStream, StreamStats, SecurityInfo};

/// Unified network stream that can wrap different platform-specific implementations
pub enum UnifiedNetworkStream {
    #[cfg(not(target_family = "wasm"))]
    Tcp(citadel_io::tokio::net::TcpStream),
    
    #[cfg(not(target_family = "wasm"))] 
    Tls(Box<citadel_wire::exports::tokio_rustls::TlsStream<citadel_io::tokio::net::TcpStream>>),
    
    #[cfg(not(target_family = "wasm"))]
    Quic {
        send_stream: citadel_wire::exports::SendStream,
        recv_stream: citadel_wire::exports::RecvStream,
        endpoint: citadel_wire::exports::Endpoint,
        connection: Option<citadel_wire::exports::Connection>,
        remote_addr: SocketAddr,
    },
    
    #[cfg(target_family = "wasm")]
    WebRtc(crate::wasm::WebRtcDataChannel),
    
    #[cfg(target_family = "wasm")]
    WebSocket(crate::wasm::WebSocketStream),
}

impl std::fmt::Debug for UnifiedNetworkStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => "TCP",
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(_) => "TLS",
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { .. } => "QUIC",
            #[cfg(target_family = "wasm")]
            Self::WebRtc(_) => "WebRTC",
            #[cfg(target_family = "wasm")]
            Self::WebSocket(_) => "WebSocket",
        };
        write!(f, "UnifiedNetworkStream({})", variant)
    }
}

impl AsyncRead for UnifiedNetworkStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { recv_stream, .. } => Pin::new(recv_stream).poll_read(cx, buf),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => {
                match Pin::new(channel).poll_read(cx, buf) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            },
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => {
                match Pin::new(stream).poll_read(cx, buf) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            },
        }
    }
}

impl AsyncWrite for UnifiedNetworkStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.as_mut().get_mut() {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { send_stream, .. } => Pin::new(send_stream).poll_write(cx, buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => Pin::new(channel).poll_write(cx, buf),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { send_stream, .. } => Pin::new(send_stream).poll_flush(cx).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => Pin::new(channel).poll_flush(cx),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Quic { send_stream, .. } => Pin::new(send_stream).poll_flush(cx).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl NetworkStream for UnifiedNetworkStream {
    fn local_addr(&self) -> NexusResult<SocketAddr> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => stream.local_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => stream.get_ref().0.local_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { endpoint, .. } => endpoint.local_addr().map_err(NexusError::from),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => channel.local_addr(),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.local_addr(),
        }
    }

    fn peer_addr(&self) -> NexusResult<SocketAddr> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => stream.peer_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => stream.get_ref().0.peer_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { remote_addr, .. } => Ok(*remote_addr),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => channel.peer_addr(),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.peer_addr(),
        }
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        use futures::AsyncWriteExt;
        
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(stream) => stream.shutdown().await.map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(stream) => stream.shutdown().await.map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { send_stream, connection, .. } => {
                send_stream.finish().map_err(|e| NexusError::Connection(e.to_string()))?;
                if let Some(conn) = connection.take() {
                    conn.close(0u32.into(), b"shutdown");
                }
                Ok(())
            }
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => channel.shutdown().await,
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.shutdown().await,
        }
    }

    fn stats(&self) -> StreamStats {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) | Self::Tls(_) => StreamStats::default(),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { .. } => StreamStats::default(), // TODO: Extract QUIC stats
            #[cfg(target_family = "wasm")]
            Self::WebRtc(channel) => channel.stats(),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.stats(),
        }
    }

    fn is_secure(&self) -> bool {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => false,
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(_) | Self::Quic { .. } => true,
            #[cfg(target_family = "wasm")]
            Self::WebRtc(_) => true, // WebRTC is always encrypted
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.is_secure(),
        }
    }

    fn security_info(&self) -> Option<SecurityInfo> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => None,
            #[cfg(not(target_family = "wasm"))]
            Self::Tls(_) => Some(SecurityInfo {
                protocol: "TLS".to_string(),
                cipher_suite: None, // TODO: Extract from rustls
                peer_certificate: None,
            }),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { .. } => Some(SecurityInfo {
                protocol: "QUIC".to_string(),
                cipher_suite: None,
                peer_certificate: None,
            }),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(_) => Some(SecurityInfo {
                protocol: "WebRTC".to_string(),
                cipher_suite: Some("DTLS-SRTP".to_string()),
                peer_certificate: None,
            }),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(stream) => stream.security_info(),
        }
    }
}

impl UnifiedNetworkStream {
    /// Get QUIC endpoint if this stream is a QUIC connection
    #[cfg(not(target_family = "wasm"))]
    pub fn quic_endpoint(&self) -> Option<quinn::Endpoint> {
        match self {
            Self::Quic { endpoint, .. } => Some(endpoint.clone()),
            _ => None,
        }
    }
    
    /// Get QUIC endpoint if this stream is a QUIC connection (WASM stub)
    #[cfg(target_family = "wasm")]
    pub fn quic_endpoint(&self) -> Option<()> {
        None
    }
    
    /// Take the QUIC connection if this stream is a QUIC connection
    #[cfg(not(target_family = "wasm"))]
    pub fn take_quic_connection(&mut self) -> Option<quinn::Connection> {
        match self {
            Self::Quic { connection, .. } => connection.take(),
            _ => None,
        }
    }
    
    /// Take the QUIC connection if this stream is a QUIC connection (WASM stub)
    #[cfg(target_family = "wasm")]
    pub fn take_quic_connection(&mut self) -> Option<()> {
        None
    }
}