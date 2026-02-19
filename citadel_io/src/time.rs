//! Platform-agnostic time module.
//!
//! On native targets, re-exports from `std::time` and `tokio::time`.
//! On WASM targets, re-exports from `wasmtimer` which uses `performance.now()`
//! for monotonic time and JS `Date.now()` for system time.

pub use std::time::Duration;

#[cfg(not(target_family = "wasm"))]
pub use crate::tokio::time::Instant;
#[cfg(target_family = "wasm")]
pub use wasmtimer::std::Instant;

#[cfg(not(target_family = "wasm"))]
pub use std::time::SystemTime;
#[cfg(target_family = "wasm")]
pub use wasmtimer::std::SystemTime;

// Async timer functions
#[cfg(not(target_family = "wasm"))]
pub use crate::tokio::time::{interval, interval_at, sleep, sleep_until, timeout};
#[cfg(target_family = "wasm")]
pub use wasmtimer::tokio::{interval, interval_at, sleep, sleep_until, timeout};

// Async timer types
#[cfg(not(target_family = "wasm"))]
pub use crate::tokio::time::{Interval, MissedTickBehavior, Sleep, Timeout};
#[cfg(target_family = "wasm")]
pub use wasmtimer::tokio::{Interval, MissedTickBehavior, Sleep, Timeout};

pub mod error {
    #[cfg(not(target_family = "wasm"))]
    pub use crate::tokio::time::error::*;
    #[cfg(target_family = "wasm")]
    pub use wasmtimer::tokio::error::*;
}

pub mod delay_queue {
    #[cfg(not(target_family = "wasm"))]
    pub use crate::tokio_util::time::delay_queue::*;
    #[cfg(target_family = "wasm")]
    pub use wasmtimer::tokio_util::delay_queue::*;
}

#[cfg(not(target_family = "wasm"))]
pub use crate::tokio_util::time::DelayQueue;
#[cfg(target_family = "wasm")]
pub use wasmtimer::tokio_util::DelayQueue;
