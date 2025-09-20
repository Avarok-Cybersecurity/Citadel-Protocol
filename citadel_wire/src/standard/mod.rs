//! Standard Network Protocol Components
//!
//! This module provides core networking components and utilities that form the
//! foundation of the Citadel Protocol's network stack. It includes implementations
//! for various standard protocols and network operations.
//!
//! # Features
//!
//! - QUIC protocol implementation
//! - TLS security and certificate management
//! - NAT traversal and identification
//! - UPnP port mapping and gateway control
//! - Socket creation and configuration
//! - Utility functions for network operations
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::{
//!     nat_identification::NatType,
//!     socket_helpers,
//!     upnp_handler::UPnPHandler
//! };
//!
//! async fn setup_network() -> Result<(), anyhow::Error> {
//!     // Identify NAT type
//!     let nat = NatType::identify(None).await?;
//!     
//!     // Setup UPnP if available
//!     if let Ok(upnp) = UPnPHandler::new(None).await {
//!         println!("UPnP available: {}", upnp);
//!     }
//!     
//!     // Create network sockets
//!     let addr: std::net::SocketAddr = "*********:8080".parse()?;
//!     let socket = socket_helpers::get_udp_socket(addr)?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Components are designed for peer-to-peer use
//! - IPv4 and IPv6 support where possible
//! - Security-first implementation approach
//! - Platform-specific behaviors handled
//! - Async-first design philosophy
//!
//! # Related Components
//!
//! - [`crate::udp_traversal`] - UDP hole punching
//! - [`crate::hypernode_type`] - Node type definitions
//! - [`crate::error`] - Error handling
//!
pub mod misc;
pub mod nat_identification;
pub mod quic;
pub mod socket_helpers;
pub mod tls;
pub mod upnp_handler;
