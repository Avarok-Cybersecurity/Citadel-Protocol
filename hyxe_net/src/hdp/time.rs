use std::fmt::{Display, Formatter};
use std::ops::AddAssign;

/// Used for keeping track of the transfer rate
#[derive(Clone)]
pub struct TransferStats {
    // nanosecond resolution
    pub timestamp: i64,
    pub plaintext_bytes_in_window: isize,
    // Rate is in bytes per second
    pub transfer_rate: f32,
    pub transfer_rate_jitter: f32,
    pub total_plaintext_bytes_sent: isize,
}

impl TransferStats {
    /// Creates a new instance of Self
    pub fn new(timestamp: i64, plaintext_bytes_sent: isize) -> Self {
        Self {
            timestamp,
            plaintext_bytes_in_window: plaintext_bytes_sent,
            transfer_rate: 0f32,
            transfer_rate_jitter: 0f32,
            total_plaintext_bytes_sent: 0,
        }
    }
}

impl AddAssign for TransferStats {
    fn add_assign(&mut self, rhs: Self) {
        let diff_ns = rhs.timestamp - self.timestamp;
        let diff_sec = (diff_ns / 1_000_000_000) as f64;
        let transfer_rate_jitter: f64 =
            ((rhs.transfer_rate - self.transfer_rate) as f64) / diff_sec;
        let transfer_rate: f64 =
            (rhs.plaintext_bytes_in_window - self.plaintext_bytes_in_window) as f64 / diff_sec;
        self.transfer_rate = transfer_rate as f32;
        self.transfer_rate_jitter = transfer_rate_jitter as f32;

        self.timestamp = rhs.timestamp;
        self.total_plaintext_bytes_sent = self
            .total_plaintext_bytes_sent
            .wrapping_add(rhs.plaintext_bytes_in_window);
        self.plaintext_bytes_in_window = rhs.plaintext_bytes_in_window;
    }
}

impl Display for TransferStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[| Transfer Rate: {}b/s, Transfer Rate Jitter: {}b/s^2, Total Plaintext Bytes Sent: {} b |]", self.transfer_rate, self.transfer_rate_jitter, self.total_plaintext_bytes_sent)
    }
}
