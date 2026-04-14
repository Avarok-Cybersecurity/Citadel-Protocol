//! Citadel Wire: Network Traversal and Connection Management
//!
//! This crate provides comprehensive networking utilities for establishing secure
//! peer-to-peer connections across residential NATs and firewalls. It implements
//! multiple NAT traversal strategies and secure connection protocols.
//!
//! # Features
//!
//! - UDP hole punching with multiple strategies
//! - NAT type detection and traversal analysis
//! - QUIC protocol support for secure connections
//! - TLS certificate and security management
//! - UPnP port mapping and gateway control
//! - Platform-specific socket configuration
//! - IPv4 and IPv6 support where available
//!
//! # Important Notes
//!
//! - Zero unsafe code policy enforced
//! - Async-first design with Tokio runtime
//! - Security-focused implementation
//! - Automatic fallback mechanisms
//! - Comprehensive error handling
//!
//! # Related Components
//!
//! - [`udp_traversal`] - UDP hole punching implementation
//! - [`standard`] - Core networking components
//! - [`hypernode_type`] - Node type definitions
//! - [`error`] - Error type definitions
//!
//! Tools for punching holes through the firewall and network. This enables functionality across residential NATs
#![deny(unsafe_code)]
#[cfg(not(target_family = "wasm"))]
pub mod exports {
    pub use openssl;
    pub use quinn::{Accept, Connecting, Connection, Endpoint, RecvStream, SendStream};
    pub use rustls::pki_types::pem::PemObject;
    pub use rustls::pki_types::{CertificateDer as Certificate, PrivateKeyDer as PrivateKey};
    pub use rustls::ClientConfig;
    pub use tokio_rustls;
}

pub mod error;
pub mod udp_traversal;

pub mod hypernode_type;
pub(crate) mod standard;

pub use standard::*;
