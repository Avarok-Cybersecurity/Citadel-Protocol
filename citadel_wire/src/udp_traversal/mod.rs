//! UDP NAT Traversal Framework
//!
//! This module provides a comprehensive framework for UDP NAT traversal,
//! implementing multiple traversal methods including UPnP, hole punching,
//! and specialized techniques. It coordinates between different traversal
//! strategies and manages connection establishment across NAT boundaries.
//!
//! # Architecture
//!
//! The framework is organized into several key components:
//!
//! - Linear traversal: Sequential hole punching attempts
//! - Multi traversal: Concurrent traversal strategies
//! - UPnP integration: Automatic port forwarding
//! - Socket management: NAT-aware socket handling
//!
//! # Features
//!
//! - Multiple NAT traversal methods
//! - Unique connection identification
//! - Method prioritization and fallback
//! - Binary serialization support
//! - Connection state tracking
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::udp_traversal::{
//!     NatTraversalMethod,
//!     HolePunchID
//! };
//!
//! // Select traversal method based on NAT type
//! let method = NatTraversalMethod::UPnP;
//! let method_byte = method.into_byte();
//!
//! // Generate unique connection ID
//! let punch_id = HolePunchID::default();
//! ```
//!
//! # Important Notes
//!
//! - UPnP requires router support
//! - Method3 is a fallback strategy
//! - Connection IDs are UUID-based
//! - Methods are tried in priority order
//! - Binary encoding is network-safe
//!
//! # Related Components
//!
//! - [`crate::standard::upnp_handler`] - UPnP support
//! - [`crate::nat_identification`] - NAT analysis
//! - [`crate::standard::socket_helpers`] - Socket utilities
//!

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

/// Linear hole-punching
pub mod linear;

pub mod hole_punched_socket;

pub mod udp_hole_puncher;

pub mod hole_punch_config;
pub mod multi;

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum NatTraversalMethod {
    UPnP,
    Method3,
    // none needed
    None,
}

impl Display for NatTraversalMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl NatTraversalMethod {
    pub fn into_byte(self) -> u8 {
        match self {
            NatTraversalMethod::UPnP => 0,
            NatTraversalMethod::Method3 => 3,
            NatTraversalMethod::None => 7,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(NatTraversalMethod::UPnP),
            3 => Some(NatTraversalMethod::Method3),
            7 => Some(NatTraversalMethod::None),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Copy, Clone)]
pub struct HolePunchID(Uuid);

impl HolePunchID {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for HolePunchID {
    fn default() -> Self {
        Self::new()
    }
}
