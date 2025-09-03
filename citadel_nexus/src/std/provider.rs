//! Standard I/O provider implementation

use async_trait::async_trait;
use std::net::SocketAddr;
//use std::sync::Arc;

use crate::error::{NexusResult, NexusError};
use crate::traits::{CitadelIOInterface, PlatformInfo, IpInfo};
use crate::unified::{UnifiedNetworkStream, UnifiedNetworkListener};
//use super::tcp::{StdTcpStream, StdTcpListener};
use super::udp::StdUdpSocket;
use super::nat::StdNatTraversal;

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
        
        Ok(Self {
            nat_traversal,
        })
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
        let listener = citadel_io::tokio::net::TcpListener::bind(addr).await
            .map_err(NexusError::from)?;
        
        Ok(UnifiedNetworkListener::Tcp(listener))
    }

    async fn connect_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpStream> {
        let stream = citadel_io::tokio::net::TcpStream::connect(addr).await
            .map_err(NexusError::from)?;
        
        Ok(UnifiedNetworkStream::Tcp(stream))
    }

    async fn bind_udp(&self, addr: SocketAddr) -> NexusResult<Self::UdpSocket> {
        let socket = citadel_io::tokio::net::UdpSocket::bind(addr).await
            .map_err(NexusError::from)?;
        
        Ok(StdUdpSocket::new(socket))
    }

    fn nat_traversal(&self) -> &Self::NatTraversal {
        &self.nat_traversal
    }

    async fn get_local_ip_info(&self) -> NexusResult<IpInfo> {
        // Use the async_ip crate to get local IP information
        let ip_info = async_ip::IpAddressInfo::localhost();

        let ipv4 = match ip_info.internal_ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        };
        let ipv6 = match ip_info.external_ipv6 {
            Some(std::net::IpAddr::V6(v6)) => Some(v6),
            _ => None,
        };
        
        Ok(IpInfo {
            ipv4,
            ipv6,
            behind_nat: None, // Will be determined by NAT traversal
        })
    }

    fn supports_ipv6(&self) -> bool {
        // TODO: Implement IPv6 detection
        false
    }

    fn supports_quic(&self) -> bool {
        cfg!(feature = "std")
    }

    fn supports_tls(&self) -> bool {
        cfg!(feature = "std")
    }

    fn platform_info(&self) -> PlatformInfo {
        PlatformInfo {
            name: "std",
            features: vec![
                "tcp", "udp", "ipv6", 
                if self.supports_tls() { "tls" } else { "" },
                if self.supports_quic() { "quic" } else { "" },
                "nat-traversal"
            ].into_iter().filter(|s| !s.is_empty()).collect(),
            max_connections: None, // No artificial limit
        }
    }
}

/// Create TLS listener with the given configuration
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub async fn create_tls_listener(
    addr: SocketAddr, 
    cert_chain: Vec<u8>, 
    private_key: Vec<u8>
) -> NexusResult<UnifiedNetworkListener> {
    use citadel_wire::exports::tokio_rustls::{TlsAcceptor, rustls};
    use citadel_wire::exports::rustls_pemfile;
    use std::io::Cursor;
    
    // Parse the certificate chain and private key
    let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NexusError::Configuration(format!("Failed to parse certificate chain: {}", e)))?;
    
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(&private_key))
        .map_err(|e| NexusError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| NexusError::Configuration("No private key found".to_string()))?;
    
    // Create server configuration
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| NexusError::Configuration(format!("Failed to create TLS config: {}", e)))?;
    
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    let tcp_listener = citadel_io::tokio::net::TcpListener::bind(addr).await
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
    private_key: Vec<u8>
) -> NexusResult<UnifiedNetworkListener> {
    use citadel_wire::exports::rustls_pemfile;
    use citadel_wire::exports::tokio_rustls::rustls;
    use quinn::{self, crypto::rustls::QuicServerConfig};
    use std::io::Cursor;
    
    // Parse the certificate chain and private key
    let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NexusError::Configuration(format!("Failed to parse certificate chain: {}", e)))?;
    
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(&private_key))
        .map_err(|e| NexusError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| NexusError::Configuration("No private key found".to_string()))?;
    
    // Create server configuration for QUIC
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| NexusError::Configuration(format!("Failed to create QUIC TLS config: {}", e)))?;
    
    let quic_server_config = QuicServerConfig::try_from(server_config)
        .map_err(|e| NexusError::Configuration(format!("Failed to create QUIC config: {}", e)))?;
    
    let mut quic_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_config));
    
    // Configure transport parameters
    let transport: &mut quinn::TransportConfig = std::sync::Arc::get_mut(&mut quic_config.transport)
        .ok_or_else(|| NexusError::Configuration("Failed to get mutable transport config".to_string()))?;
    
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()
        .map_err(|e| NexusError::Configuration(format!("Invalid timeout: {}", e)))?));
    
    // Create QUIC endpoint
    let endpoint = quinn::Endpoint::server(quic_config, addr)
        .map_err(|e| NexusError::Connection(format!("Failed to create QUIC endpoint: {}", e)))?;
    
    Ok(UnifiedNetworkListener::Quic {
        endpoint,
    })
}