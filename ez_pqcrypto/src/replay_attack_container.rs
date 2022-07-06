use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::hash::{Hasher, BuildHasher};
use std::marker::PhantomData;

/// The past HISTORY_LEN packets arrived will be saved to allow out-of-order delivery of packets
pub const HISTORY_LEN: u64 = 1024;
/// Helps ensure that each packet protected is only used once
///
/// packets that get "protected" get a unique packet ID (PID) that gets encrypted with the plaintext to ensure each packet that gets crafted
/// can only be used once. In the validation stage, if the the decrypted PID already exists, then the decryption fails.
/// NOTE: we must use a circular queue over a simple atomic incrementer because a packet with PID k + n may arrive before
/// packet with PID k. By using a circular queue, we ensure that packets may arrive out of order, and, that they can still
/// be kept tracked of within a small range (maybe 100)
///
/// This should be session-unique. There's no point to saving this, especially since re-keying occurs in the networking stack
#[derive(Serialize, Deserialize)]
pub struct AntiReplayAttackContainer {
    // the first value is the number of packets received
    history: Mutex<(u64, HashSet<u64, NoHashHasher<u64>>)>,
    // used for getting the next unique outbound PID. Each node has a unique counter
    counter_out: AtomicU64
}

const ORDERING: Ordering = Ordering::Relaxed;

impl AntiReplayAttackContainer {
    #[inline]
    pub fn get_next_pid(&self) -> u64 {
        self.counter_out.fetch_add(1, ORDERING)
    }

    /// If the value already exists, this will return an error. If not, this will save
    /// the PID in the internal circular buffer
    #[allow(unused_results)]
    pub fn on_pid_received(&self, pid_received: u64) -> bool {
        let mut queue = self.history.lock();
        //log::trace!(target: "lusna", "Circular queue: {:?}", &queue.1);
        if queue.1.contains(&pid_received) {
            log::error!(target: "lusna", "[ARA] packet {} already arrived!", pid_received);
            false
        } else {
            // this means the PID is not in the history. HOWEVER, it may still be possible that the packet
            // was withheld long enough for the history to be cleared, thus enabling a delayed replay attack.
            // To ensure we protect against a delayed replay attack, check to see that the received PID is
            // within HISTORY_LEN of counter_in
            //let min = queue.0.saturating_sub(HISTORY_LEN);
            let min = queue.0.saturating_sub(HISTORY_LEN);
            //let max = queue.0 + HISTORY_LEN;
            //log::trace!(target: "lusna", "RECV {}. Must be >= {} (st: {})", pid_received, min, queue.0);
            // TODO: Consider logic of this section of code. This may not do what I want it to do
            if pid_received >= min {
                if queue.1.len() >= HISTORY_LEN as _ {
                    let lowest = queue.0;

                    // remove the lowest value. Only increment if the lowest value exists
                    if queue.1.remove(&lowest) {
                        queue.0 += 1;
                    }
                }

                //queue.0 += 1;

                queue.1.insert(pid_received);

                true
            } else {
                log::error!(target: "lusna", "[ARA] out of range! Recv: {}. Expected >= {}", pid_received, min);
                false
            }
        }
    }

    pub fn has_tracked_packets(&self) -> bool {
        (self.counter_out.load(ORDERING) != 0)
            || (self.history.lock().0 != 0)
    }

    pub fn reset(&self) {
        self.counter_out.store(0, ORDERING);
        let mut lock = self.history.lock();
        lock.0 = 0;
        lock.1 = HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default());
    }
}

impl Default for AntiReplayAttackContainer {
    fn default() -> Self {
        Self { history: Mutex::new((0, HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default()))), counter_out: AtomicU64::new(0) }
    }
}


struct NoHashHasher<T>(u64, PhantomData<T>);

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData)
    }
}

trait IsEnabled {}

impl IsEnabled for u64 {}

impl<T: IsEnabled> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 { self.0 }

    fn write(&mut self, _: &[u8]) {
        panic!("Invalid use of NoHashHasher")
    }

    fn write_u64(&mut self, n: u64)     { self.0 = n }
}

impl<T: IsEnabled> BuildHasher for NoHashHasher<T> {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}