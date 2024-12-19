//! # Rekey State Container
//!
//! Manages cryptographic key rotation and ratchet updates in the Citadel Protocol.
//! Provides security level-based key update scheduling and state management.
//!
//! ## Features
//! - Manages stacked ratchet construction for key rotation
//! - Supports peer-to-peer key updates
//! - Handles local rekey requests and notifications
//! - Provides configurable security levels
//! - Implements adaptive update frequency based on security needs
//!
//! ## Example Usage
//! ```rust
//! use citadel_proto::proto::state_subcontainers::RatchetUpdateState;
//! use citadel_proto::proto::transfer_stats::TransferStats;
//!
//! // Create new ratchet update state
//! let mut state = RatchetUpdateState::default();
//!
//! // Calculate update frequency based on security level
//! let stats = TransferStats::default();
//! let frequency = calculate_update_frequency(2, &stats);
//! ```
//!
//! ## Important Notes
//! - Security levels range from 0 (low) to 4 (divine)
//! - Update frequencies are in nanoseconds
//! - P2P updates are tracked per connection
//! - Manual mode requires kernel notification
//! - Completion status is reported for local requests
//!
//! ## Related Components
//! - `stacked_ratchet`: Core cryptographic ratchet implementation
//! - `session`: Uses rekey state for session security
//! - `peer`: Manages peer-to-peer rekey operations
//! - `kernel`: Receives rekey completion notifications

use citadel_io::tokio::time::Duration;

use crate::constants::{
    DRILL_UPDATE_FREQUENCY_DIVINE_BASE, DRILL_UPDATE_FREQUENCY_HIGH_BASE,
    DRILL_UPDATE_FREQUENCY_LOW_BASE, DRILL_UPDATE_FREQUENCY_MEDIUM_BASE,
    DRILL_UPDATE_FREQUENCY_ULTRA_BASE,
};
use crate::error::NetworkError;
use crate::prelude::{NodeResult, ReKeyResult, ReKeyReturnType, Ticket, VirtualTargetType};
use crate::proto::outbound_sender::UnboundedSender;
use crate::proto::transfer_stats::TransferStats;
use citadel_crypt::ratchets::Ratchet;
use std::collections::HashMap;

pub struct RatchetUpdateState<R: Ratchet> {
    pub alice_stacked_ratchet: Option<R::Constructor>,
    pub p2p_updates: HashMap<u64, R::Constructor>,
    // if this is present (in the case of manual mode), an alert will be sent
    // to the kernel once the re-key has finished
    pub current_local_requests: HashMap<VirtualTargetType, Ticket>,
}

impl<R: Ratchet> Default for RatchetUpdateState<R> {
    fn default() -> Self {
        Self {
            alice_stacked_ratchet: None,
            p2p_updates: HashMap::new(),
            current_local_requests: HashMap::new(),
        }
    }
}

impl<R: Ratchet> RatchetUpdateState<R> {
    pub(crate) fn on_complete(
        &mut self,
        v_conn_type: VirtualTargetType,
        to_kernel_tx: &UnboundedSender<NodeResult>,
        status: ReKeyReturnType,
    ) -> Result<(), NetworkError> {
        if let Some(ticket) = self.current_local_requests.remove(&v_conn_type) {
            to_kernel_tx
                .unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status,
                    session_cid: v_conn_type.get_session_cid(),
                }))
                .map_err(|err| NetworkError::Generic(err.to_string()))
        } else {
            Ok(())
        }
    }
}

/// Calculates the frequency, in nanoseconds per update
pub fn calculate_update_frequency(security_level: u8, _transfer_stats: &TransferStats) -> Duration {
    match security_level {
        0 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE),

        1 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_MEDIUM_BASE),

        2 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_HIGH_BASE),

        3 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_ULTRA_BASE),

        _ => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_DIVINE_BASE),
    }
}
