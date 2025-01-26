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
//! - Calculates update frequency based on security level
//!
//! ## Important Notes
//! - Security levels range from 0 (low) to 4 (extreme)
//! - Update frequencies are in nanoseconds
//! - P2P updates are tracked per connection
//! - Manual mode requires kernel notification
//! - Completion status is reported for local requests
//!
//! ## Related Components
//! - `ratchet`: Core cryptographic ratchet implementation
//! - `session`: Uses rekey state for session security
//! - `peer`: Manages peer-to-peer rekey operations
//! - `kernel`: Receives rekey completion notifications

use citadel_io::tokio::time::Duration;

use crate::constants::{
    REKEY_UPDATE_FREQUENCY_EXTREME, REKEY_UPDATE_FREQUENCY_HIGH, REKEY_UPDATE_FREQUENCY_REINFORCED,
    REKEY_UPDATE_FREQUENCY_STANDARD, REKEY_UPDATE_FREQUENCY_ULTRA,
};
use crate::proto::transfer_stats::TransferStats;

/// Calculates the frequency, in nanoseconds per update
pub fn calculate_update_frequency(security_level: u8, _transfer_stats: &TransferStats) -> Duration {
    match security_level {
        0 => Duration::from_nanos(REKEY_UPDATE_FREQUENCY_STANDARD),
        1 => Duration::from_nanos(REKEY_UPDATE_FREQUENCY_REINFORCED),
        2 => Duration::from_nanos(REKEY_UPDATE_FREQUENCY_HIGH),
        3 => Duration::from_nanos(REKEY_UPDATE_FREQUENCY_ULTRA),
        _ => Duration::from_nanos(REKEY_UPDATE_FREQUENCY_EXTREME),
    }
}
