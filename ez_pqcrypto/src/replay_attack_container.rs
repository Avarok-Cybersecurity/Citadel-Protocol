#[cfg(not(feature = "unordered"))]
pub mod ordered {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Uses compare-and-swap operations to determine that an in-order packet is valid
    ///
    /// Use this when anticipating the use of TCP
    pub struct AntiReplayAttackContainer {
        in_counter: AtomicU64,
        out_counter: AtomicU64
    }

    impl AntiReplayAttackContainer {
        #[inline]
        pub fn get_next_pid(&self) -> u64 {
            self.out_counter.fetch_add(1, Ordering::SeqCst)
        }

        /// Returns true if the value is valid, false otherwise
        #[inline]
        pub fn on_pid_received(&self, pid: u64) -> bool {
            self.in_counter.compare_and_swap(pid, pid + 1, Ordering::SeqCst) == pid
        }

        pub fn has_tracked_packets(&self) -> bool {
            self.in_counter.load(Ordering::Relaxed) != 0
            || self.out_counter.load(Ordering::Relaxed) != 0
        }
    }

    impl Default for AntiReplayAttackContainer {
        fn default() -> Self {
            Self { in_counter: AtomicU64::new(0), out_counter: AtomicU64::new(0) }
        }
    }
}

/// When using an unordered networking protocol, this should be used to keep track
#[cfg(feature = "unordered")]
pub mod unordered {
    use parking_lot::Mutex;
    use circular_queue::CircularQueue;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The past 100 packets arrived will be saved to allow out-of-order delivery of packets
    pub const HISTORY_LEN: u64 = 50;
    /// Helps ensure that each packet protected is only used once
    ///
    /// packets that get "protected" get a unique packet ID (PID) that gets encrypted with the plaintext to ensure each packet that gets crafted
    /// can only be used once. In the validation stage, if the the decrypted PID already exists, then the decryption fails.
    /// NOTE: we must use a circular queue over a simple atomic incrementer because a packet with PID k + n may arrive before
    /// packet with PID k. By using a circular queue, we ensure that packets may arrive out of order, and, that they can still
    /// be kept tracked of within a small range (maybe 100)
    ///
    /// This should be session-unique. There's no point to saving this, especially since re-keying occurs in the networking stack
    pub struct AntiReplayAttackContainer {
        // the first value is the number of packets received
        history: Mutex<(u64, CircularQueue<u64>)>,
        // used for getting the next unique outbound PID. Each node has a unique counter
        counter_out: AtomicU64
    }

    impl AntiReplayAttackContainer {
        #[inline]
        pub fn get_next_pid(&self) -> u64 {
            self.counter_out.fetch_add(1, Ordering::SeqCst)
        }

        /// If the value already exists, this will return an error. If not, this will save
        /// the PID in the internal circular buffer
        #[allow(unused_results)]
        pub fn on_pid_received(&self, pid_received: u64) -> bool {
            let mut queue = self.history.lock();
            if let Some(_) = queue.1.iter().find(|already_arrived| **already_arrived == pid_received) {
                false
            } else {
                // this means the PID is not in the history. HOWEVER, it may still be possible that the packet
                // was withheld long enough for the history to be cleared, thus enabling a delayed replay attack.
                // To ensure we protect against a delayed replay attack, check to see that the received PID is
                // within HISTORY_LEN of counter_in
                let min = queue.0.saturating_sub(HISTORY_LEN);
                let max = queue.0 + HISTORY_LEN;

                if pid_received >= min && pid_received < max {
                    queue.0 += 1;
                    queue.1.push(pid_received);
                    true
                } else {
                    false
                }
            }
        }

        pub fn has_tracked_packets(&self) -> bool {
            (self.counter_out.load(Ordering::Relaxed) != 0)
            || (self.history.lock().0 != 0)
        }
    }

    impl Default for AntiReplayAttackContainer {
        fn default() -> Self {
            Self { history: Mutex::new((0, CircularQueue::with_capacity(HISTORY_LEN as usize))), counter_out: AtomicU64::new(0) }
        }
    }
}