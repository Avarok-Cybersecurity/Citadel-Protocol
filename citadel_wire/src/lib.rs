//! Tools for punching holes through the firewall and network. This enables functionality across residential NATs
#![forbid(unsafe_code)]
#[cfg(not(target_family = "wasm"))]
pub mod exports {
    pub use openssl;
    pub use quinn::{Accept, Connecting, Connection, Endpoint, RecvStream, SendStream};
    pub use rustls::ClientConfig;
    pub use rustls::{Certificate, PrivateKey};
    pub use rustls_pemfile;
    pub use tokio_rustls;
}

pub mod error;
pub mod udp_traversal;

pub mod hypernode_type;
pub(crate) mod standard;

pub use standard::*;
