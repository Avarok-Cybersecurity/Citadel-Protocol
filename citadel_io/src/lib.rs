//! # Citadel IO
//!
//! A cross-platform I/O utility crate that provides consistent interfaces for both native and WebAssembly targets.
//! This crate abstracts platform-specific implementations of common I/O operations, synchronization primitives,
//! and random number generation.
//!
//! ## Features
//!
//! - Cross-platform synchronization primitives (`Mutex`, `RwLock`)
//! - Platform-specific random number generation
//! - Deadlock detection (native only)
//! - Async runtime abstractions via Tokio
//! - WebAssembly-compatible implementations
//!
//! ## Platform Support
//!
//! ### Native (non-WASM)
//!
//! On native platforms, this crate uses:
//! - `parking_lot` for high-performance synchronization primitives
//! - Standard Tokio for async runtime
//! - System random number generator
//! - Optional deadlock detection
//!
//! ### WebAssembly
//!
//! On WASM targets, this crate provides:
//! - WebAssembly-compatible synchronization primitives
//! - WASM-specific random number generation
//! - WASM-compatible Tokio implementation
//!
//! ## Usage
//!
//! ```rust
//! use citadel_io::{Mutex, RwLock, ThreadRng};
//!
//! // Create thread-safe synchronization primitives
//! let mutex = Mutex::new(42);
//! let rwlock = RwLock::new(String::new());
//!
//! // Use locks safely across threads
//! {
//!     let mut guard = mutex.lock();
//!     *guard += 1;
//! }
//!
//! // Read-write lock usage
//! {
//!     let mut writer = rwlock.write();
//!     writer.push_str("Hello");
//! }
//! ```

#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(target_family = "wasm")]
pub use wasm::locks::*;

#[cfg(not(target_family = "wasm"))]
pub use standard::locks::*;

#[cfg(all(feature = "deadlock-detection", not(target_family = "wasm")))]
pub use parking_lot::deadlock;

#[cfg(not(target_family = "wasm"))]
pub use parking_lot::{const_mutex, const_rwlock};

#[cfg(not(target_family = "wasm"))]
pub use rand::prelude::*;
#[cfg(target_family = "wasm")]
pub use wasm::rng::{WasmRng as ThreadRng, *};

pub use rand::Rng;

/// Represents errors that can occur during I/O operations
#[derive(Debug)]
pub enum Error {
    /// Wraps a standard I/O error
    IoError(std::io::Error),
}

// Re-export Tokio and related crates with platform-specific implementations
#[cfg(not(target_family = "wasm"))]
pub use tokio;

#[cfg(target_family = "wasm")]
pub use tokio_wasm as tokio;

#[cfg(not(target_family = "wasm"))]
pub use tokio_util;

#[cfg(target_family = "wasm")]
pub use tokio_util_wasm as tokio_util;

#[cfg(not(target_family = "wasm"))]
pub use tokio_stream;

#[cfg(target_family = "wasm")]
pub use tokio_stream_wasm as tokio_stream;
