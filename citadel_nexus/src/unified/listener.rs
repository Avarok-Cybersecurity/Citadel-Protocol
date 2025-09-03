//! Unified listener implementations that work across platforms

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::error::{NexusResult, NexusError};
use crate::traits::{NetworkListener, ListenerStats};
use crate::unified::UnifiedNetworkStream;

/// Unified network listener that can wrap different platform-specific implementations
pub enum UnifiedNetworkListener {
    #[cfg(not(target_family = "wasm"))]
    Tcp(citadel_io::tokio::net::TcpListener),
    
    #[cfg(not(target_family = "wasm"))]
    Tls {
        listener: citadel_io::tokio::net::TcpListener,
        acceptor: citadel_wire::exports::tokio_rustls::TlsAcceptor,
    },
    
    #[cfg(not(target_family = "wasm"))]
    Quic {
        endpoint: citadel_wire::exports::Endpoint,
    },
    
    #[cfg(target_family = "wasm")]
    WebRtc(crate::wasm::WebRtcListener),
    
    #[cfg(target_family = "wasm")]
    WebSocket(crate::wasm::WebSocketListener),
}

impl Clone for UnifiedNetworkListener {
    fn clone(&self) -> Self {
        // Note: Some listeners cannot be truly cloned, so we panic for now
        // In a real implementation, you would need a different approach
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => panic!("TCP listener cannot be cloned"),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls { .. } => panic!("TLS listener cannot be cloned"),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { endpoint } => Self::Quic { endpoint: endpoint.clone() },
            #[cfg(target_family = "wasm")]
            Self::WebRtc(listener) => Self::WebRtc(listener.clone()),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => Self::WebSocket(listener.clone()),
        }
    }
}

impl std::fmt::Debug for UnifiedNetworkListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => "TCP",
            #[cfg(not(target_family = "wasm"))]
            Self::Tls { .. } => "TLS",
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { .. } => "QUIC",
            #[cfg(target_family = "wasm")]
            Self::WebRtc(_) => "WebRTC",
            #[cfg(target_family = "wasm")]
            Self::WebSocket(_) => "WebSocket",
        };
        write!(f, "UnifiedNetworkListener({})", variant)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl NetworkListener for UnifiedNetworkListener {
    type Stream = UnifiedNetworkStream;

    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(listener) => {
                let (stream, addr) = listener.accept().await.map_err(NexusError::from)?;
                Ok((UnifiedNetworkStream::Tcp(stream), addr))
            }
            
            #[cfg(not(target_family = "wasm"))]
            Self::Tls { listener, acceptor } => {
                let (stream, addr) = listener.accept().await.map_err(NexusError::from)?;
                let tls_stream = acceptor.accept(stream).await
                    .map_err(|e| NexusError::Connection(e.to_string()))?;
                Ok((UnifiedNetworkStream::Tls(Box::new(citadel_wire::exports::tokio_rustls::TlsStream::Server(tls_stream))), addr))
            }
            
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { endpoint } => {
                let connecting = endpoint.accept().await
                    .ok_or_else(|| NexusError::Connection("QUIC endpoint closed".to_string()))?;
                let connection = connecting.await
                    .map_err(|e| NexusError::Connection(e.to_string()))?;
                
                let remote_addr = connection.remote_address();
                let (send_stream, recv_stream) = connection.accept_bi().await
                    .map_err(|e| NexusError::Connection(e.to_string()))?;
                
                let stream = UnifiedNetworkStream::Quic {
                    send_stream,
                    recv_stream,
                    endpoint: endpoint.clone(),
                    connection: Some(connection),
                    remote_addr,
                };
                
                Ok((stream, remote_addr))
            }
            
            #[cfg(target_family = "wasm")]
            Self::WebRtc(listener) => {
                let (channel, addr) = listener.accept().await?;
                Ok((UnifiedNetworkStream::WebRtc(channel), addr))
            }
            
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((UnifiedNetworkStream::WebSocket(stream), addr))
            }
        }
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(listener) => listener.local_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Tls { listener, .. } => listener.local_addr().map_err(NexusError::from),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { endpoint } => endpoint.local_addr().map_err(NexusError::from),
            #[cfg(target_family = "wasm")]
            Self::WebRtc(listener) => listener.local_addr(),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    fn stats(&self) -> ListenerStats {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) | Self::Tls { .. } => ListenerStats::default(),
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { .. } => ListenerStats::default(), // TODO: Extract QUIC stats
            #[cfg(target_family = "wasm")]
            Self::WebRtc(listener) => listener.stats(),
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => listener.stats(),
        }
    }

    fn is_secure(&self) -> bool {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) => false,
            #[cfg(not(target_family = "wasm"))]
            Self::Tls { .. } | Self::Quic { .. } => true,
            #[cfg(target_family = "wasm")]
            Self::WebRtc(_) => true, // WebRTC is always encrypted
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => listener.is_secure(),
        }
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        match self {
            #[cfg(not(target_family = "wasm"))]
            Self::Tcp(_) | Self::Tls { .. } => {
                // TCP listeners don't have explicit shutdown
                Ok(())
            }
            #[cfg(not(target_family = "wasm"))]
            Self::Quic { endpoint } => {
                endpoint.close(0u32.into(), b"shutdown");
                Ok(())
            }
            #[cfg(target_family = "wasm")]
            Self::WebRtc(listener) => listener.shutdown().await,
            #[cfg(target_family = "wasm")]
            Self::WebSocket(listener) => listener.shutdown().await,
        }
    }
}