//! # Time Tracking Module
//!
//! This module provides precise time tracking utilities for network operations.
//! It uses monotonic system time to ensure consistent and reliable timing
//! measurements, particularly useful for network latency calculations and
//! timing-sensitive operations.
//!
//! ## Features
//!
//! - Nanosecond precision timing
//! - Monotonic time source
//! - Overflow protection
//! - Debug formatting
//!
//! ## Example
//!
//! ```rust
//! use netbeam::time_tracker::TimeTracker;
//!
//! let tracker = TimeTracker::new();
//! let start_time = tracker.get_global_time_ns();
//!
//! // Perform some operation
//!
//! let elapsed = tracker.get_global_time_ns() - start_time;
//! println!("Operation took {} ns", elapsed);
//! ```

use std::fmt::Formatter;

/// A utility for tracking time with nanosecond precision.
///
/// TimeTracker provides a consistent way to measure time intervals
/// using the system's monotonic clock. It is particularly useful
/// for measuring network latencies and timing-sensitive operations.
#[derive(Copy, Clone, Default)]
pub struct TimeTracker;

impl TimeTracker {
    /// Creates a new TimeTracker instance.
    ///
    /// This is equivalent to calling `Default::default()` as
    /// TimeTracker maintains no internal state.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the current global time in nanoseconds.
    ///
    /// This method returns the number of nanoseconds since the Unix epoch,
    /// modulo i64::MAX to prevent overflow. This provides approximately
    /// 100 years of unique timestamps before wrapping around.
    ///
    /// # Returns
    ///
    /// Returns the current time in nanoseconds as an i64.
    /// The returned value will wrap around after approximately 100 years.
    pub fn get_global_time_ns(&self) -> i64 {
        (std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos() % i64::MAX as u128) as i64
    }
}

/// Debug implementation for TimeTracker.
///
/// Provides a human-readable format showing the current global time
/// in nanoseconds when the TimeTracker is debug-printed.
impl std::fmt::Debug for TimeTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Time tracker current global time: {}ns",
            self.get_global_time_ns()
        )
    }
}
