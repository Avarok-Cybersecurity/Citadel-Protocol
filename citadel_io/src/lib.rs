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

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use standard::udp_io_uring::IoUringUdpReceiver;

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

/// The workspace-wide canonical error type. See [`error::NetworkError`].
pub mod error;
pub use error::{Dbg, ErrorArgs, ErrorCode, NetworkError};

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

#[cfg(not(target_family = "wasm"))]
mod native_runtime {
    /// On native, wraps a real tokio runtime Handle (needed for multi-threaded spawn).
    pub type RuntimeHandle = crate::tokio::runtime::Handle;

    /// Attempt to acquire a handle to the current async runtime.
    ///
    /// On native: calls `tokio::runtime::Handle::try_current()`.
    pub fn try_current_runtime() -> Result<RuntimeHandle, String> {
        crate::tokio::runtime::Handle::try_current().map_err(|e| e.to_string())
    }

    /// Offload a blocking closure to a dedicated thread pool.
    ///
    /// On native: delegates to `tokio::task::spawn_blocking`.
    pub fn spawn_blocking<F, R>(f: F) -> crate::tokio::task::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        crate::tokio::task::spawn_blocking(f)
    }

    /// Spawn an async task on the runtime.
    ///
    /// On native: delegates to `tokio::task::spawn`.
    pub fn spawn<F>(f: F) -> crate::tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        crate::tokio::task::spawn(f)
    }
}

#[cfg(not(target_family = "wasm"))]
pub use native_runtime::*;

#[cfg(target_family = "wasm")]
mod wasm_runtime {
    /// On WASM (always single-threaded), the handle is unused so we substitute `()`.
    pub type RuntimeHandle = ();

    /// Attempt to acquire a handle to the current async runtime.
    ///
    /// On WASM: always succeeds (returns `()`).
    pub fn try_current_runtime() -> Result<RuntimeHandle, String> {
        Ok(())
    }

    /// Offload a blocking closure to a dedicated thread pool.
    ///
    /// On WASM: runs inline (single-threaded; no blocking pool available).
    pub async fn spawn_blocking<F, R>(f: F) -> Result<R, String>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        Ok(f())
    }

    /// Spawn an async task on the runtime.
    ///
    /// On WASM: delegates to `tokio::task::spawn_local` (no multi-thread runtime).
    pub fn spawn<F>(f: F) -> crate::tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + 'static,
        F::Output: 'static,
    {
        crate::tokio::task::spawn_local(f)
    }
}

#[cfg(target_family = "wasm")]
pub use wasm_runtime::*;
