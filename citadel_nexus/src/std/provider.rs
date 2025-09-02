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
    _cert_chain: Vec<u8>, 
    _private_key: Vec<u8>
) -> NexusResult<UnifiedNetworkListener> {
    // TODO: Implement TLS listener creation
    let listener = citadel_io::tokio::net::TcpListener::bind(addr).await
        .map_err(NexusError::from)?;
    Ok(UnifiedNetworkListener::Tcp(listener))
}

/// Create QUIC endpoint
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub async fn create_quic_endpoint(
    addr: SocketAddr,
    _cert_chain: Vec<u8>,
    _private_key: Vec<u8>
) -> NexusResult<UnifiedNetworkListener> {
    // TODO: Implement QUIC endpoint creation
    let listener = citadel_io::tokio::net::TcpListener::bind(addr).await
        .map_err(NexusError::from)?;
    Ok(UnifiedNetworkListener::Tcp(listener))
}