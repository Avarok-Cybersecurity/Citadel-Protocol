//! Standard I/O provider implementation

use async_trait::async_trait;
use std::net::SocketAddr;

use super::nat::StdNatTraversal;
use super::udp::StdUdpSocket;
use crate::error::{NexusError, NexusResult};
use crate::traits::CitadelIOInterface;
use crate::unified::{UnifiedNetworkListener, UnifiedNetworkStream};

/// Standard implementation of the CitadelIOInterface for native platforms
///
/// This provider uses Tokio for async I/O operations, supporting TCP, UDP,
/// TLS via Rustls, and QUIC via Quinn.
#[derive(Debug, Clone)]
pub struct StdIOProvider {
    nat_traversal: StdNatTraversal,
}

impl StdIOProvider {
    /// Create a new standard I/O provider
    pub async fn new() -> NexusResult<Self> {
        let nat_traversal = StdNatTraversal::new().await?;

        Ok(Self { nat_traversal })
    }
}

#[async_trait]
impl CitadelIOInterface for StdIOProvider {
    type TcpListener = UnifiedNetworkListener;
    type TcpStream = UnifiedNetworkStream;
    type UdpSocket = StdUdpSocket;
    type NatTraversal = StdNatTraversal;

    async fn new() -> NexusResult<Self> {
        Self::new().await
    }

    async fn bind_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpListener> {
        let listener = citadel_io::tokio::net::TcpListener::bind(addr)
            .await
            .map_err(NexusError::from)?;

        Ok(UnifiedNetworkListener::Tcp(listener))
    }

    async fn connect_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpStream> {
        let stream = citadel_io::tokio::net::TcpStream::connect(addr)
            .await
            .map_err(NexusError::from)?;

        Ok(UnifiedNetworkStream::Tcp(stream))
    }

    async fn bind_udp(&self, addr: SocketAddr) -> NexusResult<Self::UdpSocket> {
        let socket = citadel_io::tokio::net::UdpSocket::bind(addr).await?;
        Ok(StdUdpSocket::new(socket))
    }

    async fn get_local_ip_addrs(&self) -> NexusResult<Vec<std::net::IpAddr>> {
        use std::net::IpAddr;

        let mut addrs = Vec::new();

        // Try to get IPv4 address
        if let Some(ipv4) = async_ip::get_internal_ipv4().await {
            addrs.push(ipv4);
        }

        // Try to get IPv6 address
        if let Some(ipv6) = async_ip::get_internal_ip(true).await {
            if !addrs.contains(&ipv6) {
                addrs.push(ipv6);
            }
        }

        // If no addresses found, return localhost as fallback
        if addrs.is_empty() {
            addrs.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        }

        Ok(addrs)
    }

    fn nat_traversal(&self) -> &Self::NatTraversal {
        &self.nat_traversal
    }
}

/// Create TLS listener with the given configuration
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub async fn create_tls_listener(
    addr: SocketAddr,
    cert_chain: Vec<u8>,
    private_key: Vec<u8>,
) -> NexusResult<UnifiedNetworkListener> {
    use citadel_wire::exports::rustls_pemfile;
    use citadel_wire::exports::tokio_rustls::{rustls, TlsAcceptor};
    use std::io::Cursor;

    // Parse the certificate chain and private key
    let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            NexusError::Configuration(format!("Failed to parse certificate chain: {}", e))
        })?;

    let private_key = rustls_pemfile::private_key(&mut Cursor::new(&private_key))
        .map_err(|e| NexusError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| NexusError::Configuration("No private key found".to_string()))?;

    // Create server configuration
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| NexusError::Configuration(format!("Failed to create TLS config: {}", e)))?;

    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    let tcp_listener = citadel_io::tokio::net::TcpListener::bind(addr)
        .await
        .map_err(NexusError::from)?;

    Ok(UnifiedNetworkListener::Tls {
        listener: tcp_listener,
        acceptor,
    })
}

/// Create QUIC endpoint
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub async fn create_quic_endpoint(
    addr: SocketAddr,
    cert_chain: Vec<u8>,
    private_key: Vec<u8>,
) -> NexusResult<UnifiedNetworkListener> {
    use citadel_wire::exports::rustls_pemfile;
    use citadel_wire::exports::tokio_rustls::rustls;
    use quinn::{self, crypto::rustls::QuicServerConfig};
    use std::io::Cursor;

    // Parse the certificate chain and private key
    let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            NexusError::Configuration(format!("Failed to parse certificate chain: {}", e))
        })?;

    let private_key = rustls_pemfile::private_key(&mut Cursor::new(&private_key))
        .map_err(|e| NexusError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| NexusError::Configuration("No private key found".to_string()))?;

    // Create server configuration for QUIC
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| {
            NexusError::Configuration(format!("Failed to create QUIC TLS config: {}", e))
        })?;

    let quic_server_config = QuicServerConfig::try_from(server_config)
        .map_err(|e| NexusError::Configuration(format!("Failed to create QUIC config: {}", e)))?;

    let mut quic_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_config));

    // Configure transport parameters
    let transport: &mut quinn::TransportConfig =
        std::sync::Arc::get_mut(&mut quic_config.transport).ok_or_else(|| {
            NexusError::Configuration("Failed to get mutable transport config".to_string())
        })?;

    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|e| NexusError::Configuration(format!("Invalid timeout: {}", e)))?,
    ));

    // Create QUIC endpoint
    let endpoint = quinn::Endpoint::server(quic_config, addr)
        .map_err(|e| NexusError::Connection(format!("Failed to create QUIC endpoint: {}", e)))?;

    Ok(UnifiedNetworkListener::Quic { endpoint })
}
