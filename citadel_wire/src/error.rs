//! Error Types for Network Traversal and Firewall Operations
//!
//! Firewall / NAT-traversal errors are part of the workspace-wide canonical
//! [`citadel_io::NetworkError`]. This module re-exports it under the historical
//! [`FirewallError`] alias so existing call sites keep compiling.
//!
//! # Features
//!
//! - Canonical, `Clone`able error value shared across the workspace
//! - Conversion traits between the canonical error and standard IO errors
//!   (provided by `citadel_io`)
//! - Stable [`citadel_io::ErrorCode`] discriminants for firewall scenarios
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::error::FirewallError;
//! use std::io::Error;
//!
//! // Create a UPnP error
//! let upnp_err = FirewallError::firewall_upnp("Port mapping failed");
//!
//! // Convert to standard IO error
//! let io_err: Error = upnp_err.into();
//! ```
//!
//! # Important Notes
//!
//! - [`FirewallError::firewall_skip`] indicates operation should be skipped
//! - [`FirewallError::firewall_not_applicable`] for unsupported operations
//! - [`FirewallError::firewall_hole_punch_exhausted`] when all attempts fail
//!
//! # Related Components
//!
//! - [`crate::standard::upnp_handler`] - UPnP operations
//! - [`crate::udp_traversal`] - Hole punching operations
//! - [`crate::hypernode_type`] - Node configuration

pub type FirewallError = citadel_io::NetworkError;
