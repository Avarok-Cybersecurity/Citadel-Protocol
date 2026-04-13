//! Standard platform implementation using Tokio and related crates
//!
//! This module provides the implementation of the Citadel Nexus traits for
//! standard Rust targets using Tokio for async I/O, Quinn for QUIC, and
//! Rustls for TLS support.

pub mod nat;
pub mod provider;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use nat::StdNatTraversal;
pub use provider::StdIOProvider;
pub use tcp::{StdTcpListener, StdTcpStream};
pub use udp::StdUdpSocket;
