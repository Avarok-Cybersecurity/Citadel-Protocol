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
        let queued = self.queued.fetch_add(len, Ordering::AcqRel) + len;
        if queued > self.limit {
            let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        true
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
