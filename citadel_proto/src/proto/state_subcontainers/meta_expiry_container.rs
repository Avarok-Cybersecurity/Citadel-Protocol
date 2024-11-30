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
//! ## Example Usage
//! ```rust
//! use citadel_proto::proto::state_subcontainers::MetaExpiryState;
//!
//! let mut state = MetaExpiryState::default();
//!
//! // Update state on packet confirmation
//! state.on_event_confirmation();
//!
//! // Check if expired
//! if state.expired() {
//!     // Handle expiration
//! }
//! ```
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

/// In cases where a surge of packets are being processed, some groups may falsely be marked as expired, when really, the async executor hasn't had the opportunity to process them yet
/// This is where this container comes to the rescue. If a group is detected as expired, this container should be checked to see if there has been recent progress on other groups
/// This works for both inbound and outbound direction for groups, as well as files (which will make use of the outbound direction for checking)
/// under low to medium traffic workloads, this probably won't matter. This is for high workloads
pub struct MetaExpiryState {
    last_valid_event: Instant,
}

impl MetaExpiryState {
    pub fn expired(&self) -> bool {
        self.last_valid_event.elapsed() > GROUP_EXPIRE_TIME_MS
    }
    /// Whenever a packet is confirmed, call this
    pub fn on_event_confirmation(&mut self) {
        self.last_valid_event = Instant::now()
    }
}

impl Default for MetaExpiryState {
    fn default() -> Self {
        Self {
            last_valid_event: Instant::now(),
        }
    }
}
