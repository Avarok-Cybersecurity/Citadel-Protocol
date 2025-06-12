//! Error Types for Network Traversal and Firewall Operations
//!
//! This module defines error types specific to network traversal and firewall
//! operations in the Citadel Protocol. It handles errors from UPnP port forwarding,
//! hole punching, and other network-related operations.
//!
//! # Features
//!
//! - Custom error types for UPnP and hole punching operations
//! - Conversion traits between custom and standard IO errors
//! - Descriptive error messages for debugging
//! - Error categorization for different network scenarios
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::error::FirewallError;
//! use std::io::Error;
//!
//! // Create a UPnP error
//! let upnp_err = FirewallError::UPNP("Port mapping failed".to_string());
//!
//! // Convert to standard IO error
//! let io_err: Error = upnp_err.into();
//! ```
//!
//! # Important Notes
//!
//! - `FirewallError::Skip` indicates operation should be skipped
//! - `FirewallError::NotApplicable` for unsupported operations
//! - `FirewallError::HolePunchExhausted` when all attempts fail
//! - Implements standard error traits for interoperability
//!
//! # Related Components
//!
//! - [`crate::standard::upnp_handler`] - UPnP operations
//! - [`crate::udp_traversal`] - Hole punching operations
//! - [`crate::hypernode_type`] - Node configuration
//!

use citadel_io::tokio::io::Error;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum FirewallError {
    UPNP(String),
    HolePunch(String),
    Skip,
    NotApplicable,
    HolePunchExhausted,
    LocalIPAddrFail,
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FirewallError::UPNP(err) | FirewallError::HolePunch(err) => err,
                FirewallError::NotApplicable => "Method not applicable to local node",
                FirewallError::HolePunchExhausted => "No more NAT traversal methods exist",
                FirewallError::LocalIPAddrFail => "Unable to obtain local IP info",
                FirewallError::Skip => "Skipped",
            }
        )
    }
}

impl std::error::Error for FirewallError {}

impl From<FirewallError> for std::io::Error {
    fn from(val: FirewallError) -> Self {
        std::io::Error::other(val.to_string())
    }
}

impl From<std::io::Error> for FirewallError {
    fn from(err: Error) -> Self {
        FirewallError::HolePunch(err.to_string())
    }
}
