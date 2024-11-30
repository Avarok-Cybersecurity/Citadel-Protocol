//! Node Type Configuration for Network Topology
//!
//! This module defines the network node types and their behaviors in the Citadel
//! Protocol. It supports both traditional client-server and peer-to-peer network
//! topologies.
//!
//! # Features
//!
//! - Server configuration with static IP addresses
//! - Peer configuration for residential NAT environments
//! - Automatic UPnP handling for peer nodes
//! - Fallback to NAT traversal when UPnP is unavailable
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::hypernode_type::NodeType;
//! use std::net::SocketAddr;
//!
//! // Configure a server with static IP
//! let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//! let server = NodeType::server(addr).unwrap();
//! assert!(server.is_server());
//!
//! // Configure a peer node (residential NAT)
//! let peer = NodeType::default();
//! assert!(peer.is_peer());
//! ```
//!
//! # Important Notes
//!
//! - Server nodes must have stable, reachable IP addresses
//! - Peer nodes automatically attempt UPnP port forwarding
//! - Fallback to NAT traversal for symmetric NATs
//! - Socket addresses are validated during construction
//!
//! # Related Components
//!
//! - [`crate::udp_traversal`] - NAT traversal functionality
//! - [`crate::standard::upnp_handler`] - UPnP port forwarding
//! - [`crate::standard::socket_helpers`] - Socket utilities
//!

use std::net::{SocketAddr, ToSocketAddrs};

/// Used for determining the proper action when loading the server
#[derive(Default, Copy, Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub enum NodeType {
    /// A server with a static IP address will choose this option
    Server(SocketAddr),
    /// A client/server behind a residential NAT will choose this (will specially will start the UPnP handler, but the method for symmetrical NATs works too; UPnP is just faster)
    #[default]
    Peer,
}

impl NodeType {
    pub fn server<T: ToSocketAddrs>(addr: T) -> Result<Self, anyhow::Error> {
        addr.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::Error::msg("Invalid input server socket address"))
            .map(NodeType::Server)
    }

    pub fn bind_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Server(addr) => Some(*addr),
            _ => None,
        }
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::Server(..))
    }

    pub fn is_peer(&self) -> bool {
        matches!(self, Self::Peer)
    }
}
