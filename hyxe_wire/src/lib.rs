//! Tools for punching holes through the firewall and network. This enables functionality across residential NATs
#![forbid(unsafe_code)]
pub mod exports {
    pub use igd::PortMappingProtocol;
    pub use quinn::{Connecting, Connection, Endpoint, Incoming, NewConnection, RecvStream, SendStream};
    pub use rustls::{Certificate, PrivateKey};
    pub use tokio_rustls;
    pub use rustls::ClientConfig;
    pub use openssl;
    pub use rustls_pemfile;
}

pub mod ip_addr;

pub mod upnp_handler;

pub mod error;

pub mod udp_traversal;

pub mod nat_identification;

pub mod local_firewall_handler;

pub mod hypernode_type;

pub mod socket_helpers;

pub mod quic;

pub mod tls;

pub mod misc;