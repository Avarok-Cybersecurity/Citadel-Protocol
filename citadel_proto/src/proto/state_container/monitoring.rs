//! Keep-alive monitoring for [`StateContainerInner`].

use super::includes::*;

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
        if let Some(prev_ka_time) = self.network_stats.last_keep_alive {
            //assert_ne!(self.keep_alive_timeout_ns, 0);
            current_timestamp_ns - prev_ka_time > self.keep_alive_timeout_ns
        } else {
            false
        }
    }
}
