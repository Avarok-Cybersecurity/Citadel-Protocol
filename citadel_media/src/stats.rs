/// Monotonic counters for a media session. Zero-initialized via `Default` (not a config).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaStats {
    pub frames_sent: u64,
    pub fragments_sent: u64,
    pub bytes_sent: u64,
    pub frames_dropped_on_send: u64,
    pub fragments_received: u64,
    pub bytes_received: u64,
    pub frames_completed: u64,
    pub fragments_duplicate: u64,
    pub fragments_rejected: u64,
    pub frames_evicted_incomplete: u64,
    pub frames_late: u64,
    pub frames_too_old: u64,
    pub frames_delivered: u64,
    pub gaps_skipped: u64,
    pub frames_missing: u64,
}

impl MediaStats {
    pub const fn new() -> Self {
        Self {
            frames_sent: 0,
            fragments_sent: 0,
            bytes_sent: 0,
            frames_dropped_on_send: 0,
            fragments_received: 0,
            bytes_received: 0,
            frames_completed: 0,
            fragments_duplicate: 0,
            fragments_rejected: 0,
            frames_evicted_incomplete: 0,
            frames_late: 0,
            frames_too_old: 0,
            frames_delivered: 0,
            gaps_skipped: 0,
            frames_missing: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        assert_eq!(MediaStats::default(), MediaStats::new());
        assert_eq!(MediaStats::default().frames_sent, 0);
    }
}
