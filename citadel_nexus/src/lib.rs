//! # Citadel Nexus: Cross-Platform I/O Abstraction
//!
//! Citadel Nexus provides a unified I/O abstraction layer that enables the Citadel Protocol 
//! to work across different platforms, particularly standard (STD) and WebAssembly (WASM) targets.
//! This crate sits between the protocol layer and platform-specific I/O implementations.
//!
//! ## Features
//!
//! - **Cross-platform networking**: Unified API for TCP, UDP, and secure transports
//! - **NAT traversal abstraction**: Platform-agnostic hole punching and traversal
//! - **WebAssembly support**: WebRTC DataChannels and WebSocket implementations
//! - **Type-safe abstractions**: Compile-time guarantees for platform compatibility
//! - **Performance focused**: Zero-cost abstractions where possible
//!
//! ## Architecture
//!
//! The crate is structured around the [`CitadelIOInterface`] trait, which provides
//! platform-specific implementations of networking operations. Platform-specific
//! modules provide concrete implementations:
//!
//! - [`std`]: Standard Rust/Tokio implementation for native platforms
//! - [`wasm`]: WebAssembly implementation using WebRTC and WebSockets
//! - [`traits`]: Core trait definitions and abstractions
//! - [`unified`]: Common unified types that work across platforms
//!
//! ## Usage
//!
//! ```rust,no_run
//! use citadel_nexus::{CitadelIOInterface, DefaultIOProvider};
//! 
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let io_provider = DefaultIOProvider::new().await?;
//!     let listener = io_provider.bind_tcp("127.0.0.1:0".parse()?).await?;
//!     // Use the listener for protocol operations...
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! ### Standard (STD) Targets
//! - Full TCP/UDP support via Tokio
//! - QUIC support via Quinn
//! - TLS support via Rustls
//! - Complete NAT traversal capabilities
//!
//! ### WebAssembly (WASM) Targets  
//! - WebRTC DataChannels for reliable streams
//! - WebSocket fallback for compatibility
//! - Browser-based STUN/TURN for NAT traversal
//! - Limited UDP support via WebRTC unreliable channels

#![forbid(unsafe_code)]

pub mod error;
pub mod traits;
pub mod unified;

#[cfg(not(target_family = "wasm"))]
pub mod std;

#[cfg(target_family = "wasm")]
pub mod wasm;

// Re-export core traits
pub use traits::*;

// Re-export unified types
pub use unified::*;

// Platform-specific default providers
#[cfg(not(target_family = "wasm"))]
pub use std::StdIOProvider as DefaultIOProvider;

#[cfg(target_family = "wasm")]
pub use wasm::WasmIOProvider as DefaultIOProvider;

/// Current version of the Citadel Nexus crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");