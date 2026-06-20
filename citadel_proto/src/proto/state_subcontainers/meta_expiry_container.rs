//! # Meta Expiry State Container
//!
//! Manages expiration state for high-traffic packet processing scenarios in the Citadel Protocol.
//! Prevents false expiration of active groups during high workload conditions.
//!
//! ## Features
//! - Tracks packet processing events for group activity
//! - Prevents premature group expiration under high load
//! - Supports both inbound and outbound traffic monitoring
//! - Handles file transfer expiry tracking
//! - Provides adaptive expiry timing based on workload
//!
//! ## Important Notes
//! - Critical for high-traffic workload scenarios
//! - Prevents false expiration during async processing delays
//! - Maintains group and file transfer reliability
//! - Uses constant GROUP_EXPIRE_TIME_MS for timing
//!
//! ## Related Components
//! - `group_channel`: Uses expiry state for group management
//! - `packet_processor`: Integrates with packet processing flow
//! - `file_transfer`: Uses expiry state for file operations

use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::proto::packet_processor::includes::Instant;
use std::sync::atomic::{AtomicU64, Ordering};

/// In cases where a surge of packets are being processed, some groups may falsely be marked as expired, when really, the async executor hasn't had the opportunity to process them yet
/// This is where this container comes to the rescue. If a group is detected as expired, this container should be checked to see if there has been recent progress on other groups
/// This works for both inbound and outbound direction for groups, as well as files (which will make use of the outbound direction for checking)
/// under low to medium traffic workloads, this probably won't matter. This is for high workloads
pub struct MetaExpiryState {
    // Lock-free: `on_event_confirmation` runs on every confirmed packet (the inbound hot path). We
    // store nanoseconds-since-`base` in an atomic instead of a `Mutex<Instant>`, so concurrent vconns
    // never serialize here. `fetch_max` keeps the newest timestamp even with racing writers (the world
    // the inbound read-lock granularization creates); the local monotonic `base` preserves the original
    // "elapsed since the last confirmed event" semantics exactly (wall-elapsed, not network time).
    base: Instant,
    last_valid_ns: AtomicU64,
}

impl MetaExpiryState {
    pub fn expired(&self) -> bool {
        let now_ns = self.base.elapsed().as_nanos() as u64;
        let last_ns = self.last_valid_ns.load(Ordering::Relaxed);
        now_ns.saturating_sub(last_ns) > GROUP_EXPIRE_TIME_MS.as_nanos() as u64
    }
    /// Whenever a packet is confirmed, call this
    pub fn on_event_confirmation(&self) {
        let now_ns = self.base.elapsed().as_nanos() as u64;
        self.last_valid_ns.fetch_max(now_ns, Ordering::Relaxed);
    }
}

impl Default for MetaExpiryState {
    fn default() -> Self {
        // last_valid_ns = 0 == base, so a freshly-built state is "not expired" (elapsed ~0), matching
        // the old `last_valid_event = Instant::now()` initialization.
        Self {
            base: Instant::now(),
            last_valid_ns: AtomicU64::new(0),
        }
    }
}
