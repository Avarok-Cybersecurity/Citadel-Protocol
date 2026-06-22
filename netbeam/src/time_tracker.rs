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
use std::time::Duration;

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

    /// Returns the current wall-clock time in nanoseconds since the Unix epoch (modulo i64::MAX).
    ///
    /// NOTE: this is **wall-clock** (`SystemTime`) time, not a monotonic clock, so it can jump
    /// backward/forward across NTP adjustments. Callers must not rely on it being monotonic.
    /// It is safe for the distributed-lock arbitration tie-break (`net_mutex`/`net_rwlock`) because
    /// each side generates its timestamp locally and *transmits* it; both peers then compare the
    /// identical pair of absolute values with a strict ordering (ties broken deterministically by
    /// `RelativeNodeType`), so exactly one side wins regardless of clock skew. Skew affects only
    /// fairness (which side is deemed "first"), never mutual exclusion.
    ///
    /// # Returns
    ///
    /// Returns the current time in nanoseconds as an i64.
    /// The returned value will wrap around after approximately 100 years.
    ///
    /// This never panics: in the pathological case where the system clock is set *before* the Unix
    /// epoch (so `elapsed()` reports a backwards duration), we return that duration negated rather
    /// than unwrapping. The result stays a valid, strictly-ordered `i64`, so the distributed-lock
    /// tie-break still picks exactly one winner — only fairness is affected, never mutual exclusion.
    pub fn get_global_time_ns(&self) -> i64 {
        // `map_err(|e| e.duration())` normalizes the native and wasm `SystemTimeError` types to a
        // plain backwards `Duration`, keeping `ns_since_epoch` free of platform-specific types.
        ns_since_epoch(
            citadel_io::time::UNIX_EPOCH
                .elapsed()
                .map_err(|e| e.duration()),
        )
    }
}

/// Convert the result of `UNIX_EPOCH.elapsed()` into a nanosecond timestamp without panicking.
///
/// `Ok(dur)` is time after the epoch (the normal case) and yields a positive value; `Err(back)`
/// carries how far the clock is *before* the epoch and yields the negated value. Both branches take
/// the nanosecond count modulo `i64::MAX` so the cast can never overflow.
fn ns_since_epoch(elapsed: Result<Duration, Duration>) -> i64 {
    match elapsed {
        Ok(dur) => (dur.as_nanos() % i64::MAX as u128) as i64,
        Err(back) => -((back.as_nanos() % i64::MAX as u128) as i64),
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

#[cfg(test)]
mod tests {
    use super::{ns_since_epoch, TimeTracker};
    use std::time::Duration;

    #[test]
    fn forward_clock_is_positive() {
        assert_eq!(ns_since_epoch(Ok(Duration::from_nanos(0))), 0);
        assert_eq!(ns_since_epoch(Ok(Duration::from_nanos(1_500))), 1_500);
    }

    #[test]
    fn pre_epoch_clock_is_negative_not_a_panic() {
        // `elapsed()` returns Err carrying the backwards duration when the clock is before the
        // epoch; previously this path unwrapped and panicked.
        assert_eq!(ns_since_epoch(Err(Duration::from_nanos(0))), 0);
        assert_eq!(ns_since_epoch(Err(Duration::from_nanos(2_000))), -2_000);
    }

    #[test]
    fn huge_durations_wrap_without_overflowing_the_cast() {
        // Far beyond i64::MAX nanoseconds (~292 years): must stay in range, never panic on cast.
        let huge = Duration::from_secs(u64::MAX);
        let forward = ns_since_epoch(Ok(huge));
        let backward = ns_since_epoch(Err(huge));
        assert!(forward >= 0);
        assert!(backward <= 0);
        assert_eq!(forward, -backward);
    }

    #[test]
    fn real_clock_is_after_epoch() {
        // Sanity check against the actual system clock used in CI.
        assert!(TimeTracker::new().get_global_time_ns() > 0);
    }
}
