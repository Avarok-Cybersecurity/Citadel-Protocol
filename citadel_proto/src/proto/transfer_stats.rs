//! Transfer Statistics Tracking Module
//!
//! This module provides functionality for tracking and calculating network transfer statistics
//! including transfer rates, jitter, and total bytes transferred.
//!
//! # Features
//! - Tracks transfer rates with nanosecond precision
//! - Calculates transfer rate jitter (rate of change in transfer speed)
//! - Maintains running totals of plaintext bytes sent
//! - Thread-safe statistics accumulation
//!
//! # Important Notes
//! - Timestamps are in nanoseconds for high precision rate calculations
//! - Transfer rates are calculated in bytes per second
//! - Uses wrapping addition for total bytes to handle potential overflows
//!
//! # Related Components
//! - Used in conjunction with packet handling and session management modules
//! - Integral part of the protocol's performance monitoring system

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
            (rhs.plaintext_bytes_in_window as f64 - self.transfer_rate as f64) / diff_sec;
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

#[cfg(test)]
mod tests {
    use crate::proto::transfer_stats::TransferStats;

    #[test]
    fn test_tx_time() {
        let mut ts0 = TransferStats::new(0, 0);
        // assume 1 second passed by (1 bil ns in 1 sec)
        let ts1 = TransferStats::new(1_000_000_000, 50_000);
        let ts2 = TransferStats::new(2_000_000_000, 60_000);

        assert_eq!(ts0.plaintext_bytes_in_window, 0isize);
        assert_eq!(ts0.transfer_rate, 0f32);
        assert_eq!(ts0.total_plaintext_bytes_sent, 0isize);
        assert_eq!(ts0.transfer_rate_jitter, 0f32);
        assert_eq!(ts0.timestamp, 0i64);

        ts0 += ts1;

        assert_eq!(ts0.plaintext_bytes_in_window, 50_000isize);
        assert_eq!(ts0.transfer_rate, 50_000f32);
        assert_eq!(ts0.total_plaintext_bytes_sent, 50_000isize);
        assert_eq!(ts0.transfer_rate_jitter, 50_000f32); // 0 until next time, we need 2 samples
        assert_eq!(ts0.timestamp, 1_000_000_000i64);

        ts0 += ts2;

        assert_eq!(ts0.plaintext_bytes_in_window, 60_000isize);
        assert_eq!(ts0.transfer_rate, 10_000f32); // 10_000 bytes added since last ts
        assert_eq!(ts0.total_plaintext_bytes_sent, 110_000isize);
        assert_eq!(ts0.transfer_rate_jitter, 10_000f32); // delta from 50,000 to 60,000
        assert_eq!(ts0.timestamp, 2_000_000_000i64);
    }
}
