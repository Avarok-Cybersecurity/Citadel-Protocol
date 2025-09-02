//! Standard platform implementation using Tokio and related crates
//!
//! This module provides the implementation of the Citadel Nexus traits for
//! standard Rust targets using Tokio for async I/O, Quinn for QUIC, and
//! Rustls for TLS support.

pub mod provider;
pub mod tcp;
pub mod udp;
pub mod nat;
pub mod quic;
pub mod tls;

pub use provider::StdIOProvider;
pub use tcp::{StdTcpStream, StdTcpListener};
pub use udp::StdUdpSocket;
pub use nat::StdNatTraversal;