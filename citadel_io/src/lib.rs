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

pub mod proto_io;
pub use proto_io::{
    ProtocolIO, ProtocolUpgrade, ServerMode, UnreliableDatagram, UpgradeListenerPair,
};

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
pub use rand::RngCore;

/// Represents errors that can occur during I/O operations
#[derive(Debug)]
pub enum Error {
    /// Wraps a standard I/O error
    IoError(std::io::Error),
}

pub mod time;

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

/// On native, wraps a real tokio runtime Handle (needed for multi-threaded spawn).
/// On WASM (always single-threaded), the handle is unused so we substitute `()`.
#[cfg(not(target_family = "wasm"))]
pub type RuntimeHandle = tokio::runtime::Handle;
#[cfg(target_family = "wasm")]
pub type RuntimeHandle = ();

/// Attempt to acquire a handle to the current async runtime.
///
/// On native: calls `tokio::runtime::Handle::try_current()`.
/// On WASM: always succeeds (returns `()`).
pub fn try_current_runtime() -> Result<RuntimeHandle, String> {
    #[cfg(not(target_family = "wasm"))]
    {
        tokio::runtime::Handle::try_current().map_err(|e| e.to_string())
    }
    #[cfg(target_family = "wasm")]
    {
        Ok(())
    }
}

/// Offload a blocking closure to a dedicated thread pool.
///
/// On native: delegates to `tokio::task::spawn_blocking`.
/// On WASM: runs inline (single-threaded; no blocking pool available).
#[cfg(not(target_family = "wasm"))]
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// Offload a blocking closure to a dedicated thread pool.
///
/// On native: delegates to `tokio::task::spawn_blocking`.
/// On WASM: runs inline (single-threaded; no blocking pool available).
#[cfg(target_family = "wasm")]
pub async fn spawn_blocking<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    Ok(f())
}

/// Spawn an async task on the runtime.
///
/// On native: delegates to `tokio::task::spawn`.
/// On WASM: delegates to `tokio::task::spawn_local` (no multi-thread runtime).
#[cfg(not(target_family = "wasm"))]
pub fn spawn<F>(f: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::task::spawn(f)
}

/// Spawn an async task on the runtime.
///
/// On native: delegates to `tokio::task::spawn`.
/// On WASM: delegates to `tokio::task::spawn_local` (no multi-thread runtime).
#[cfg(target_family = "wasm")]
pub fn spawn<F>(f: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + 'static,
    F::Output: 'static,
{
    tokio::task::spawn_local(f)
}
