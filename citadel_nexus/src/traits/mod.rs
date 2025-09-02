//! Core trait definitions for the Citadel Nexus abstraction layer
//!
//! This module defines the fundamental traits that enable cross-platform I/O
//! operations in the Citadel Protocol. These traits abstract away the underlying
//! platform differences between standard Rust targets and WebAssembly.

pub mod interface;
pub mod stream;
pub mod listener;
pub mod datagram;
pub mod secure;
pub mod nat;

// Re-export all public traits
pub use interface::*;
pub use stream::*;
pub use listener::*;
pub use datagram::*;
pub use secure::*;
pub use nat::*;