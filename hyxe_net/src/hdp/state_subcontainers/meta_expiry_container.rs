use crate::hdp::packet_processor::includes::Instant;
use crate::constants::GROUP_EXPIRE_TIME_MS;

/// In cases where a surge of packets are being processed, some groups may falsely be marked as expired, when really, the async executor hasn't had the opportunity to process them yet
/// This is where this container comes to the rescue. If a group is detected as expired, this container should be checked to see if there has been recent progress on other groups
/// This works for both inbound and outbound direction for groups, as well as files (which will make use of the outbound direction for checking)
/// under low to medium traffic workloads, this probably won't matter. This is for high workloads
pub struct MetaExpiryState {
    last_valid_event: Instant
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
        Self { last_valid_event: Instant::now() }
    }
}