//! # Connection Metadata Management
//!
//! This module manages connection metadata for the Citadel Protocol, handling
//! connection information storage and protocol specifications for client-side
//! connections.
//!
//! ## Features
//!
//! * **Connection Information**
//!   - Socket address storage
//!   - Connection state persistence
//!   - Connection display formatting
//!
//! * **Protocol Support**
//!   - TCP connections
//!   - TLS with optional domain
//!   - QUIC with optional domain
//!
//! * **Serialization**
//!   - Serde compatibility
//!   - Debug formatting
//!   - Display implementation
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_user::connection_metadata::{ConnectionInfo, ConnectProtocol};
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//!
//! fn manage_connections() {
//!     // Create connection info
//!     let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
//!     let connection = ConnectionInfo { addr };
//!     
//!     // Create different protocol types
//!     let tcp = ConnectProtocol::Tcp;
//!     let tls = ConnectProtocol::Tls(Some("example.com".to_string()));
//!     let quic = ConnectProtocol::Quic(Some("quic.example.com".to_string()));
//!     
//!     // Get domain information
//!     assert_eq!(tcp.get_domain(), None);
//!     assert_eq!(tls.get_domain(), Some("example.com".to_string()));
//!     assert_eq!(quic.get_domain(), Some("quic.example.com".to_string()));
//!     
//!     // Display connection info
//!     println!("Connection: {}", connection);
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Connection info is serializable for persistence
//! * Protocol types support optional domain names
//! * TCP connections don't use domain information
//! * Connection display shows socket address
//! * All types implement Clone and Debug
//!
//! ## Related Components
//!
//! * `ClientNetworkAccount` - Uses connection metadata
//! * `AccountManager` - Manages connection states
//! * `PersistenceHandler` - Stores connection info
//! * `citadel_wire` - Network communication
//!

use crate::misc::AccountError;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// For saving the state of client-side connections
pub struct ConnectionInfo {
    /// The address of the adjacent node
    pub addr: SocketAddr,
}

impl ConnectionInfo {
    pub fn new<T: std::net::ToSocketAddrs>(addr: T) -> Result<ConnectionInfo, AccountError> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| AccountError::msg("No socket address"))?;
        Ok(ConnectionInfo { addr })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// For saving the state of client-side connections
pub enum ConnectProtocol {
    /// Uses the transmission control protocol
    Tcp,
    /// The domain
    Tls(Option<String>),
    /// Quic
    Quic(Option<String>),
}

impl ConnectProtocol {
    /// Gets domain
    pub fn get_domain(&self) -> Option<String> {
        match self {
            Self::Tcp => None,
            Self::Tls(t) => t.clone(),
            Self::Quic(t) => t.clone(),
        }
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "addr: {}", self.addr)
    }
}
