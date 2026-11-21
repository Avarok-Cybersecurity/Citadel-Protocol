//! The bytes all of a server's peer-facing streams may hold queued together.
//!
//! Every stream's queued bytes also count here. A send that would take the node past its total
//! ends the stream holding the most, which may be another one: a stream whose peer reads keeps
//! little queued, so the one ended is the one whose peer has fallen furthest behind.

use crate::proto::outbound_budget::OutboundBudget;
use citadel_io::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

pub(crate) struct OutboundTotal {
    limit: usize,
    queued: AtomicUsize,
    streams: Mutex<Vec<Weak<OutboundBudget>>>,
}

impl OutboundTotal {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            queued: AtomicUsize::new(0),
            streams: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Counts a new stream, whose bytes it may later have to end to stay within the total.
    pub(crate) fn enrol(&self, stream: &Arc<OutboundBudget>) {
        let mut streams = self.streams.lock();
        streams.retain(|stream| stream.strong_count() > 0);
        streams.push(Arc::downgrade(stream));
    }

    /// Counts `len` more bytes, if they fit.
    pub(crate) fn charge(&self, len: usize) -> bool {
        charge_within(&self.queued, len, self.limit)
    }

    pub(crate) fn release(&self, len: usize) {
        let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
    }

    /// The stream still going that holds the most bytes; `sender` wins a tie, so a stream is
    /// never ended for one that holds no more than it does.
    pub(crate) fn heaviest(&self, sender: &Arc<OutboundBudget>) -> Arc<OutboundBudget> {
        let streams = self.streams.lock();
        streams
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|stream| !stream.is_exhausted() && !Arc::ptr_eq(stream, sender))
            .fold(sender.clone(), |heaviest, stream| {
                if stream.queued() > heaviest.queued() {
                    stream
                } else {
                    heaviest
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

/// Adds `len` to `queued` if the sum stays within `limit`. The sum is checked, so a limit near
/// `usize::MAX` (on a 32-bit target, 4 GiB) cannot wrap the count past it.
pub(crate) fn charge_within(queued: &AtomicUsize, len: usize, limit: usize) -> bool {
    let mut now = queued.load(Ordering::Acquire);
    loop {
        let Some(sum) = now.checked_add(len).filter(|sum| *sum <= limit) else {
            return false;
        };
        match queued.compare_exchange_weak(now, sum, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => now = current,
        }
    }
}
