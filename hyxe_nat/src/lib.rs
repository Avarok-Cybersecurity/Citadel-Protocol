//! Tools for punching holes through the firewall. This enables functionality across residential NATs
#![feature(async_closure, ip)]
pub mod exports {
    pub use igd::PortMappingProtocol;
    pub use quinn::{RecvStream, SendStream, Incoming, Endpoint, Connecting, Connection, NewConnection, CertificateChain, PrivateKey};
    pub use tokio_rustls;
}

pub mod ip_addr;

pub mod upnp_handler;

pub mod error;

pub mod udp_traversal;

pub mod nat_identification;

pub mod time_tracker;

pub mod local_firewall_handler;

pub mod hypernode_type;

pub mod socket_helpers;

pub mod reliable_conn;

pub mod quic;

pub mod tls;

pub mod misc;

pub mod sync;