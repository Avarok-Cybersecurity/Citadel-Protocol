//! Tools for punching holes through the firewall and network. This enables functionality across residential NATs
#![forbid(unsafe_code)]
pub mod exports {
    pub use igd::PortMappingProtocol;
    pub use openssl;
    pub use quinn::{Accept, Connecting, Connection, Endpoint, RecvStream, SendStream};
    pub use rustls::ClientConfig;
    pub use rustls::{Certificate, PrivateKey};
    pub use rustls_pemfile;
    pub use tokio_rustls;
}

pub mod ip_addr;

pub mod upnp_handler;

pub mod error;

pub mod udp_traversal;

pub mod nat_identification;

pub mod hypernode_type;

pub mod socket_helpers;

pub mod quic;

pub mod tls;

pub mod misc;
