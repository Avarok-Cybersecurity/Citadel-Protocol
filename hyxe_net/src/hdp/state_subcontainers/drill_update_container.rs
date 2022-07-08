use tokio::time::Duration;

use crate::constants::{
    DRILL_UPDATE_FREQUENCY_DIVINE_BASE, DRILL_UPDATE_FREQUENCY_HIGH_BASE,
    DRILL_UPDATE_FREQUENCY_LOW_BASE, DRILL_UPDATE_FREQUENCY_MEDIUM_BASE,
    DRILL_UPDATE_FREQUENCY_ULTRA_BASE,
};
use crate::hdp::time::TransferStats;
use hyxe_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use std::collections::HashMap;

#[derive(Default)]
pub struct RatchetUpdateState {
    pub alice_hyper_ratchet: Option<StackedRatchetConstructor>,
    pub p2p_updates: HashMap<u64, StackedRatchetConstructor>,
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
