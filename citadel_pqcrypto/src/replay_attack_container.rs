//! Replay Attack Prevention for Secure Communications
//!
//! This module provides protection against replay attacks in cryptographic
//! communications by tracking and validating packet identifiers (PIDs).
//!
//! # Features
//!
//! - Thread-safe packet ID generation and tracking
//! - Circular buffer for efficient history management
//! - Support for out-of-order packet delivery
//! - Protection against delayed replay attacks
//! - Automatic state reset on re-keying
//!
//! # How It Works
//!
//! 1. Each outgoing packet is assigned a unique, monotonically increasing PID
//! 2. PIDs are encrypted along with packet payloads
//! 3. Received PIDs are checked against a history window
//! 4. Duplicate or out-of-window PIDs are rejected as replay attacks
//!
//! # Examples
//!
//! ```rust
//! use citadel_pqcrypto::replay_attack_container::AntiReplayAttackContainer;
//!
//! // Create a new container
//! let container = AntiReplayAttackContainer::default();
//!
//! // Generate PID for outgoing packet
//! let pid = container.get_next_pid();
//!
//! // Check incoming packet's PID
//! if container.on_pid_received(pid) {
//!     // Process packet - it's valid
//! } else {
//!     // Reject packet - potential replay attack
//! }
//! ```
//!
//! # Security Considerations
//!
//! - Window size affects protection against out-of-order delivery
//! - PIDs must be encrypted to prevent tampering
//! - State should be reset when re-keying occurs
//! - Thread-safety is critical for concurrent access
//! - Memory usage scales with window size
//!
//! # Related Components
//!
//! - [`citadel_pqcrypto::wire`] - Wire protocol implementation
//! - [`citadel_pqcrypto::key_store`] - Key management
//! - [`citadel_types::crypto`] - Cryptographic types

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

/// The past HISTORY_LEN packets arrived will be saved to allow out-of-order delivery of packets
pub const HISTORY_LEN: u64 = 1024;
/// Helps ensure that each packet protected is only used once
///
/// packets that get "protected" get a unique packet ID (PID) that gets encrypted with the plaintext to ensure each packet that gets crafted
/// can only be used once. In the validation stage, if the the decrypted PID already exists, then the decryption fails.
/// NOTE: we must use a circular queue over a simple atomic incrementer because a packet with PID k + n may arrive before
/// packet with PID k. By using a circular queue, we ensure that packets may arrive out of order, and, that they can still
/// be kept tracked of within a small range (maybe 100)
///
/// This should be session-unique. There's no point to saving this, especially since re-keying occurs in the networking stack
#[derive(Serialize, Deserialize)]
pub struct AntiReplayAttackContainer {
    // the first value is the number of packets received
    history: Mutex<(u64, HashSet<u64, NoHashHasher<u64>>)>,
    // used for getting the next unique outbound PID. Each node has a unique counter
    counter_out: AtomicU64,
}

const ORDERING: Ordering = Ordering::Relaxed;

impl AntiReplayAttackContainer {
    #[inline]
    pub fn get_next_pid(&self) -> u64 {
        self.counter_out.fetch_add(1, ORDERING)
    }

    /// Validates a received PID against a sliding anti-replay window and records it.
    ///
    /// Returns `true` if the PID is fresh (and records it), or `false` if it is a replay
    /// (already seen) or too old (below the window floor).
    ///
    /// The window is `[high_water - HISTORY_LEN, high_water)` where `high_water` is one past the
    /// largest PID accepted so far (stored in `history.0`). Within that window, out-of-order
    /// delivery is permitted; every accepted PID is remembered in `history.1` so exact duplicates
    /// are rejected, and PIDs older than the floor are rejected outright (delayed-replay defense).
    /// The remembered set is bounded to at most `HISTORY_LEN` entries: as the floor advances,
    /// PIDs that drop below it are evicted, so memory cannot grow without bound.
    #[allow(unused_results)]
    pub fn on_pid_received(&self, pid_received: u64) -> bool {
        let mut queue = self.history.lock();
        let (high_water, seen) = &mut *queue;

        // Floor of the acceptance window: the lowest PID we will still consider. PIDs below the
        // floor have aged out of the window and are rejected to prevent delayed replays.
        let floor = high_water.saturating_sub(HISTORY_LEN);

        if pid_received < floor {
            log::error!(target: "citadel", "[ARA] out of window! Recv: {pid_received}. Floor: {floor}");
            return false;
        }

        if !seen.insert(pid_received) {
            // Already present => exact replay.
            log::error!(target: "citadel", "[ARA] packet {pid_received} already arrived!");
            return false;
        }

        // Advance the high-water mark (one past the largest accepted PID) and evict any entries
        // that have fallen below the new floor, keeping the tracked set bounded.
        let new_high_water = (*high_water).max(pid_received.saturating_add(1));
        let new_floor = new_high_water.saturating_sub(HISTORY_LEN);
        if new_floor > floor {
            if new_floor.saturating_sub(floor) >= HISTORY_LEN {
                // Large forward jump: cheaper to retain than to remove one-by-one.
                seen.retain(|&pid| pid >= new_floor);
            } else {
                for stale in floor..new_floor {
                    seen.remove(&stale);
                }
            }
        }
        *high_water = new_high_water;

        true
    }

    pub fn has_tracked_packets(&self) -> bool {
        (self.counter_out.load(ORDERING) != 0) || (self.history.lock().0 != 0)
    }

    pub fn reset(&self) {
        self.counter_out.store(0, ORDERING);
        let mut lock = self.history.lock();
        lock.0 = 0;
        lock.1 = HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default());
    }
}

impl Default for AntiReplayAttackContainer {
    fn default() -> Self {
        Self {
            history: Mutex::new((
                0,
                HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default()),
            )),
            counter_out: AtomicU64::new(0),
        }
    }
}

struct NoHashHasher<T>(u64, PhantomData<T>);

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData)
    }
}

trait IsEnabled {}

impl IsEnabled for u64 {}

impl<T: IsEnabled> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _: &[u8]) {
        panic!("Invalid use of NoHashHasher")
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n
    }
}

impl<T: IsEnabled> BuildHasher for NoHashHasher<T> {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{AntiReplayAttackContainer, HISTORY_LEN};

    #[test]
    fn accepts_in_order_pids() {
        let ara = AntiReplayAttackContainer::default();
        for pid in 0..2048u64 {
            assert!(
                ara.on_pid_received(pid),
                "in-order pid {pid} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_exact_duplicates() {
        let ara = AntiReplayAttackContainer::default();
        assert!(ara.on_pid_received(5));
        assert!(!ara.on_pid_received(5), "exact replay must be rejected");
        // Other fresh pids near it still work.
        assert!(ara.on_pid_received(6));
        assert!(!ara.on_pid_received(6));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let ara = AntiReplayAttackContainer::default();
        assert!(ara.on_pid_received(10));
        // Earlier pids within the window arrive late: still accepted exactly once.
        assert!(ara.on_pid_received(3));
        assert!(ara.on_pid_received(7));
        assert!(!ara.on_pid_received(3), "late-but-seen pid is a replay");
    }

    #[test]
    fn rejects_pids_below_window_floor() {
        let ara = AntiReplayAttackContainer::default();
        // Advance the high-water mark far ahead.
        let high = HISTORY_LEN * 4;
        assert!(ara.on_pid_received(high));
        // Anything more than HISTORY_LEN below the high-water mark has aged out and is rejected,
        // closing the delayed-replay window.
        assert!(
            !ara.on_pid_received(high - HISTORY_LEN - 1),
            "pid below the floor must be rejected"
        );
        // A pid just inside the window is still accepted.
        assert!(ara.on_pid_received(high - HISTORY_LEN + 1));
    }

    #[test]
    fn tracked_set_stays_bounded() {
        let ara = AntiReplayAttackContainer::default();
        // Feed far more than HISTORY_LEN strictly-increasing pids; the tracked set must not grow
        // without bound (the previous implementation grew unboundedly).
        for pid in 0..(HISTORY_LEN * 8) {
            assert!(ara.on_pid_received(pid));
        }
        let len = ara.history.lock().1.len() as u64;
        assert!(
            len <= HISTORY_LEN + 1,
            "tracked set len {len} exceeded window bound {HISTORY_LEN}"
        );
    }

    #[test]
    fn large_forward_jump_is_bounded_and_evicts_old() {
        let ara = AntiReplayAttackContainer::default();
        assert!(ara.on_pid_received(0));
        assert!(ara.on_pid_received(1));
        // Huge jump forward: old low pids must age out of the window.
        let high = HISTORY_LEN * 100;
        assert!(ara.on_pid_received(high));
        assert!(!ara.on_pid_received(0), "pid 0 aged out after the jump");
        let len = ara.history.lock().1.len() as u64;
        assert!(
            len <= HISTORY_LEN + 1,
            "tracked set len {len} not bounded after jump"
        );
    }
}
