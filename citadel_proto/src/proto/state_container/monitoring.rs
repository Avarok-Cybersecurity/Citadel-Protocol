//! Keep-alive monitoring for [`StateContainerInner`].

use super::includes::*;
use crate::constants::KEEP_ALIVE_TIMEOUT_NS;

impl<R: Ratchet> StateContainerInner<R> {
    /// When a keep alive is received, this function gets called. Prior to getting called,
    /// validity must be ensured!
    #[allow(unused_results)]
    pub fn on_keep_alive_received(
        &mut self,
        inbound_packet_timestamp_ns: i64,
        mut current_timestamp_ns: i64,
    ) -> bool {
        if self.keep_alive_timeout_ns == 0 {
            return true;
        }

        let mut ping_ns = current_timestamp_ns - inbound_packet_timestamp_ns;
        if ping_ns < 0 {
            // For localhost testing, this sometimes occurs. The clocks might be out of sync a bit.
            current_timestamp_ns -= ping_ns;
            // Negate it, for now. Usually, this wont happen on networks
            ping_ns = -ping_ns;
        }
        // The jitter is the differential of pings. Ping current - ping present
        let jitter_ns = ping_ns - self.network_stats.ping_ns.unwrap_or(0);
        self.network_stats.jitter_ns.replace(jitter_ns);
        self.network_stats.ping_ns.replace(ping_ns);

        //log::trace!(target: "citadel", "KEEP ALIVE subsystem statistics: Ping: {}ms | RTT: {}ms | Jitter: {}ms", (ping_ns as f64/1_000_000f64) as f64, (self.network_stats.rtt_ns.clone().unwrap_or(0) as f64/1_000_000f64) as f64, (jitter_ns as f64/1000000f64) as f64);
        if let Some(last_ka) = self.network_stats.last_keep_alive.take() {
            if ping_ns > self.keep_alive_timeout_ns {
                // possible timeout. There COULD be packets being spammed, preventing KAs from getting through. Thus, check the meta expiry container
                !self.meta_expiry_state.expired()
            } else {
                self.network_stats
                    .last_keep_alive
                    .replace(current_timestamp_ns);
                // We subtract two keep alive intervals, since it pauses that long on each end. We multiply by 1 million to convert ms to ns
                const PROCESS_TIME_NS: i64 = 2 * KEEP_ALIVE_INTERVAL_MS as i64 * 1_000_000;
                self.network_stats
                    .rtt_ns
                    .replace(current_timestamp_ns - last_ka - PROCESS_TIME_NS);
                true
            }
        } else {
            // This is the first KA in the series
            self.network_stats
                .last_keep_alive
                .replace(current_timestamp_ns);
            true
        }
    }

    /// This should be ran periodically by the session timer
    pub fn keep_alive_subsystem_timed_out(&self, current_timestamp_ns: i64) -> bool {
        keep_alive_timed_out(
            self.network_stats.last_keep_alive,
            self.network_stats.measured_since_ns,
            current_timestamp_ns,
            self.keep_alive_timeout_ns,
        )
    }
}

/// The shortest keep-alive timeout a server holds a client to. A keep-alive reaches the server
/// once every two intervals (each end waits one before answering), so below three intervals an
/// honest session would be dropped between two of its keep-alives.
pub(crate) const MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS: i64 = KEEP_ALIVE_TIMEOUT_NS;

/// The longest: how long a server holds a session that has stopped proving it is alive, however
/// long its client asked for.
pub(crate) const MAX_SERVER_KEEP_ALIVE_TIMEOUT_NS: i64 = 4 * KEEP_ALIVE_TIMEOUT_NS;

/// The keep-alive timeout a server applies to a client that asked for `requested_ns`. A client
/// may disable keep-alives on its own side (0), but not the server's check on it.
pub(crate) fn server_keep_alive_timeout_ns(requested_ns: i64) -> i64 {
    requested_ns.clamp(
        MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS,
        MAX_SERVER_KEEP_ALIVE_TIMEOUT_NS,
    )
}

/// Whether a session whose last keep-alive arrived at `last_keep_alive_ns` (none yet: its clock
/// started at `since_ns`) has, at `now_ns`, gone longer than `timeout_ns` without one.
pub(crate) fn keep_alive_timed_out(
    last_keep_alive_ns: Option<i64>,
    since_ns: i64,
    now_ns: i64,
    timeout_ns: i64,
) -> bool {
    now_ns.saturating_sub(last_keep_alive_ns.unwrap_or(since_ns)) > timeout_ns
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "monitoring_tests.rs"]
mod tests;
