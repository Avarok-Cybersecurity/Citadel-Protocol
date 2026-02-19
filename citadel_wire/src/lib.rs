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

#[cfg(target_family = "wasm")]
pub mod exports {
    /// WASM connection type — designed to hold a browser transport connection.
    /// Will wrap WebRTC PeerConnection in future phases.
    /// On WASM, `Box<dyn Any>` downcasts to this type succeed when a connection exists.
    #[derive(Clone, Debug)]
    pub struct Connection;

    /// WASM endpoint type — designed to hold a browser transport endpoint.
    /// Will wrap WebSocket/WebRTC signaling in future phases.
    #[derive(Clone, Debug)]
    pub struct Endpoint;

    /// WASM receive stream — will wrap browser transport receive half.
    pub struct RecvStream;

    /// WASM send stream — will wrap browser transport send half.
    pub struct SendStream;

    /// Stub rustls module for WASM.
    /// Browser handles TLS natively; these types exist for API compatibility.
    pub mod tokio_rustls {
        pub mod rustls {
            /// Browser TLS config — the browser handles TLS natively.
            /// This type exists for `Box<dyn Any>` downcast compatibility.
            #[derive(Clone, Debug)]
            pub struct ClientConfig;

            pub mod pki_types {
                #[derive(Clone, Debug)]
                pub struct CertificateDer;
                #[derive(Clone, Debug)]
                pub struct PrivateKeyDer;
            }
        }
    }

    pub use self::tokio_rustls::rustls::ClientConfig;
}

pub mod error;
pub mod udp_traversal;

pub mod hypernode_type;
pub(crate) mod standard;

pub use standard::*;
