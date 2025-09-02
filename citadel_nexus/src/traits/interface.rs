//! Core I/O interface trait definition

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::error::NexusResult;
use super::{NetworkListener, NetworkStream, DatagramSocket, NatTraversal};

/// The main trait that provides cross-platform I/O operations for the Citadel Protocol.
/// 
/// This trait abstracts all networking operations needed by the protocol, allowing
/// for different implementations on different targets (STD vs WASM).
///
/// # Type Parameters
/// 
/// The trait uses associated types to allow platform-specific implementations of
/// network primitives while maintaining a consistent interface.
///
/// # Example
///
/// ```rust,no_run
/// use citadel_nexus::{CitadelIOInterface, DefaultIOProvider};
/// use std::net::SocketAddr;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = DefaultIOProvider::new().await?;
///     
///     // Bind a TCP listener
///     let addr: SocketAddr = "127.0.0.1:0".parse()?;
///     let listener = provider.bind_tcp(addr).await?;
///     
///     // Connect to a remote address
///     let stream = provider.connect_tcp(addr).await?;
///     
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait CitadelIOInterface: Send + Sync + Clone + 'static {
    /// TCP listener type for this platform
    type TcpListener: NetworkListener + Send + Sync + 'static;
    
    /// TCP stream type for this platform  
    type TcpStream: NetworkStream + Send + Sync + 'static;
    
    /// UDP socket type for this platform
    type UdpSocket: DatagramSocket + Send + Sync + 'static;
    
    /// NAT traversal implementation for this platform
    type NatTraversal: NatTraversal + Send + Sync + 'static;

    /// Create a new I/O provider instance
    async fn new() -> NexusResult<Self> where Self: Sized;

    /// Bind a TCP listener to the specified address
    async fn bind_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpListener>;

    /// Connect to a TCP address
    async fn connect_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpStream>;

    /// Bind a UDP socket to the specified address  
    async fn bind_udp(&self, addr: SocketAddr) -> NexusResult<Self::UdpSocket>;

    /// Get NAT traversal capabilities
    fn nat_traversal(&self) -> &Self::NatTraversal;

    /// Get local IP address information
    async fn get_local_ip_info(&self) -> NexusResult<IpInfo>;

    /// Check if IPv6 is available on this platform
    fn supports_ipv6(&self) -> bool;

    /// Check if this platform supports QUIC
    fn supports_quic(&self) -> bool;

    /// Check if this platform supports TLS
    fn supports_tls(&self) -> bool;

    /// Get platform-specific information
    fn platform_info(&self) -> PlatformInfo;
}

/// Information about the current platform
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    /// Platform name (e.g., "std", "wasm")
    pub name: &'static str,
    
    /// Supported features
    pub features: Vec<&'static str>,
    
    /// Maximum concurrent connections (if limited)
    pub max_connections: Option<usize>,
}

/// IP address information for the local system
#[derive(Debug, Clone)]
pub struct IpInfo {
    /// Local IPv4 address (if available)
    pub ipv4: Option<std::net::Ipv4Addr>,
    
    /// Local IPv6 address (if available)  
    pub ipv6: Option<std::net::Ipv6Addr>,
    
    /// Whether the system is behind NAT
    pub behind_nat: Option<bool>,
}