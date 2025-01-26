//! Builder Module for Citadel Protocol Configuration
//!
//! This module provides builder patterns for configuring and constructing various
//! components of the Citadel Protocol. The builders ensure type-safe and validated
//! configuration of network nodes and related components.
//!
//! # Features
//! - Type-safe configuration building
//! - Validation of component configurations
//! - Flexible node setup for different network roles
//!
//! # Components
//! - [`node_builder`]: Builder for configuring and constructing network nodes
//!
//! # Related Modules
//! - [`citadel_proto::kernel`]: Core networking kernel implementation
//! - [`citadel_proto::proto`]: Protocol implementation details
//!

pub mod node_builder;
