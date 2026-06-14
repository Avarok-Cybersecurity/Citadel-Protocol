//! StateContainer lock-contention profiling (opt-in `lock-profiling` feature).
//!
//! When the feature is enabled, the multi-threaded `inner_state!` / `inner_mut_state!` macros — which
//! are used *exclusively* on `*.state_container` — time each lock acquire-wait and accumulate it into
//! the global counters here. The metric that matters is **average acquire-wait**: under no contention
//! parking_lot hands out the guard in tens of nanoseconds; under a write-lock convoy the wait balloons.
//! Comparing avg acquire-wait at low vs high vconn counts cleanly attributes the multi-vconn bench's
//! throughput ceiling to the lock (wait grows) vs. raw CPU saturation (wait stays flat).
//!
//! This module compiles only under the feature, so default builds carry none of it.

// `snapshot`/`reset`/`LockStats` accessors are consumed by external benches/diagnostics, not within
// this crate, so the lib's `deny(dead_code)` would otherwise flag them.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static WRITE_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);
static WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);
static READ_COUNT: AtomicU64 = AtomicU64::new(0);

/// Record one write-lock acquisition that blocked for `wait`.
#[inline]
pub fn record_write(wait: Duration) {
    WRITE_WAIT_NANOS.fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
    WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record one read-lock acquisition that blocked for `wait`.
#[inline]
pub fn record_read(wait: Duration) {
    READ_WAIT_NANOS.fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
    READ_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Acquire a write guard, recording the acquire-wait. Returns the guard as a single expression so the
/// `inner_mut_state!` macro stays expression-shaped (preserving `&mut` deref-coercion at call sites).
#[inline]
pub fn timed_write<T>(lock: &citadel_io::RwLock<T>) -> citadel_io::RwLockWriteGuard<'_, T> {
    let t0 = std::time::Instant::now();
    let guard = lock.write();
    record_write(t0.elapsed());
    guard
}

/// Acquire a read guard, recording the acquire-wait. See [`timed_write`].
#[inline]
pub fn timed_read<T>(lock: &citadel_io::RwLock<T>) -> citadel_io::RwLockReadGuard<'_, T> {
    let t0 = std::time::Instant::now();
    let guard = lock.read();
    record_read(t0.elapsed());
    guard
}

/// A point-in-time view of the accumulated StateContainer lock counters.
#[derive(Debug, Clone, Copy)]
pub struct LockStats {
    pub write_wait_nanos: u64,
    pub write_count: u64,
    pub read_wait_nanos: u64,
    pub read_count: u64,
}

impl LockStats {
    /// Mean write-lock acquire-wait in nanoseconds (0 if no writes recorded).
    pub fn avg_write_wait_ns(&self) -> f64 {
        if self.write_count == 0 {
            0.0
        } else {
            self.write_wait_nanos as f64 / self.write_count as f64
        }
    }

    /// Mean read-lock acquire-wait in nanoseconds (0 if no reads recorded).
    pub fn avg_read_wait_ns(&self) -> f64 {
        if self.read_count == 0 {
            0.0
        } else {
            self.read_wait_nanos as f64 / self.read_count as f64
        }
    }
}

/// Read the current counters without disturbing them.
pub fn snapshot() -> LockStats {
    LockStats {
        write_wait_nanos: WRITE_WAIT_NANOS.load(Ordering::Relaxed),
        write_count: WRITE_COUNT.load(Ordering::Relaxed),
        read_wait_nanos: READ_WAIT_NANOS.load(Ordering::Relaxed),
        read_count: READ_COUNT.load(Ordering::Relaxed),
    }
}

/// Zero all counters (call before a measurement window).
pub fn reset() {
    WRITE_WAIT_NANOS.store(0, Ordering::Relaxed);
    WRITE_COUNT.store(0, Ordering::Relaxed);
    READ_WAIT_NANOS.store(0, Ordering::Relaxed);
    READ_COUNT.store(0, Ordering::Relaxed);
}
