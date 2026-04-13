//! Core trait definitions for the Citadel Nexus abstraction layer
//!
//! This module defines the fundamental traits that enable cross-platform I/O
//! operations in the Citadel Protocol. These traits abstract away the underlying
//! platform differences between standard Rust targets and WebAssembly.

pub mod datagram;
pub mod interface;
pub mod listener;
pub mod nat;
pub mod secure;
pub mod stream;

// Re-export all public traits
pub use datagram::*;
pub use interface::*;
pub use listener::*;
pub use nat::*;
pub use secure::*;
pub use stream::*;
