use tokio::time::Duration;
use tokio::time::Instant;

use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use hyxe_crypt::drill::Drill;

use crate::constants::{DRILL_UPDATE_FREQUENCY_DIVINE_BASE, DRILL_UPDATE_FREQUENCY_HIGH_BASE, DRILL_UPDATE_FREQUENCY_LOW_BASE, DRILL_UPDATE_FREQUENCY_MEDIUM_BASE, DRILL_UPDATE_FREQUENCY_ULTRA_BASE, DRILL_UPDATE_TIMEOUT_NS};
use crate::hdp::hdp_packet::packet_flags;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::time::TransferStats;

pub struct DrillUpdateState {
    pub(crate) last_stage: u8,
    /// Serves as a semaphore
    pub(crate) in_progress: bool,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) new_drill: Option<Drill>,
    pub(crate) last_update_time: Option<Instant>,
    pub(crate) last_packet_time: Option<i64>,
    pub(crate) current_ticket: Option<Ticket>,
}

impl Default for DrillUpdateState {
    fn default() -> Self {
        Self { last_stage: 0, in_progress: false, nonce: None, new_drill: None, last_update_time: None, last_packet_time: None, current_ticket: None }
    }
}

impl DrillUpdateState {
    /// Determines if self needs to update
    pub fn needs_update(&mut self, security_level: u8, transfer_stats: &TransferStats) -> bool {
        if self.in_progress {
            return false;
        }

        if let Some(last_update_time) = self.last_update_time.as_mut() {
            let update_offset = crate::hdp::state_subcontainers::drill_update_container::calculate_update_frequency(security_level, transfer_stats);
            //let update_offset = Duration::from_millis(4000);
            let elapsed = last_update_time.elapsed();
            //log::info!("Calculated update frequency: {}ms", update_offset.as_millis());
            //log::info!("Elapsed time since last completed drill update: {:?}", elapsed);
            if elapsed > update_offset {
                //log::info!("DRILL UPDATE required! Calculated offset: {:?}", update_offset);
                *last_update_time = Instant::now();
                true
            } else {
                false
            }
        } else {
            self.last_update_time = Some(Instant::now());
            false
        }
    }

    /// This should be called when beginning the subroutine. Ticket should be some if requested by the kernel
    pub fn on_begin_update_subroutine(&mut self, timestamp: i64, ticket: Option<Ticket>) {
        self.last_packet_time = Some(timestamp);
        self.current_ticket = ticket;
        self.in_progress = true;
    }

    /// Whenever a *valid* DO_DRILL_UPDATE packet is received, call this
    pub fn on_packet_received(&mut self, timestamp: i64) {
        self.last_packet_time = Some(timestamp);
    }

    /// When the drill update process finished, call this
    pub fn on_success(&mut self) {
        self.in_progress = false;
        self.last_update_time = Some(Instant::now());
        self.last_stage = packet_flags::cmd::aux::do_drill_update::STAGE0;
        self.last_packet_time = None;
        self.current_ticket = None;
    }

    /// Call this when the subroutine fails
    pub fn on_fail(&mut self) {
        self.on_success();
    }

    /// This should be periodically polled. If this returns true, the entire session should end for security purposes
    pub fn has_expired(&self, current_time: i64) -> bool {
        if self.in_progress {
            let last_packet_stamp = self.last_packet_time.as_ref().unwrap();
            if current_time - *last_packet_stamp > DRILL_UPDATE_TIMEOUT_NS {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Calculates the frequency, in nanoseconds per update
pub fn calculate_update_frequency(security_level: u8, _transfer_stats: &TransferStats) -> Duration {
    match security_level {
        0 => {
            Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE)
        }

        1 => {
            Duration::from_nanos(DRILL_UPDATE_FREQUENCY_MEDIUM_BASE)
        }

        2 => {
            Duration::from_nanos(DRILL_UPDATE_FREQUENCY_HIGH_BASE)
        }

        3 => {
            Duration::from_nanos(DRILL_UPDATE_FREQUENCY_ULTRA_BASE)
        }

        4 => {
            Duration::from_nanos(DRILL_UPDATE_FREQUENCY_DIVINE_BASE)
        }

        _ => {
            panic!("Invalid security level!")
        }
    }
}