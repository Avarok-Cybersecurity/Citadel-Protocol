//! How many bytes may wait in a peer-facing stream's outbound queue.
//!
//! A stream's queue grows only as fast as its peer reads, so a peer that stops reading would
//! otherwise grow it without bound. Each peer-facing stream (a session's primary stream, and a
//! direct P2P stream) carries an [`OutboundBudget`]: once the bytes queued and not yet taken by
//! the writer would exceed it, the stream is over. Every later send fails, and the writer's
//! receiver ends, which ends the stream and the session it carries.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The most bytes a peer-facing stream holds queued for its writer. Packets reach the queue
/// paced by what the peer acknowledges: a file transfer keeps about one and a half
/// 10 MiB groups unacknowledged, so this admits more than a dozen concurrent transfers to one
/// slow peer, while bounding what a peer that has stopped reading can make this node hold.
pub(crate) const MAX_QUEUED_OUTBOUND_BYTES: usize = 256 * 1024 * 1024;

pub(crate) struct OutboundBudget {
    limit: usize,
    queued: AtomicUsize,
    exhausted: AtomicBool,
}

impl OutboundBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            queued: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
        }
    }

    /// Whether `len` more bytes may be queued. Once one send is refused, every later one is.
    pub(crate) fn admit(&self, len: usize) -> bool {
        if self.is_exhausted() {
            return false;
        }
        let queued = self.queued.fetch_add(len, Ordering::AcqRel) + len;
        if queued > self.limit {
            let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
            self.exhausted.store(true, Ordering::Release);
            log::warn!(target: "citadel", "Outbound queue would exceed {} bytes; the peer is not reading. Ending the stream.", self.limit);
            return false;
        }
        true
    }

    /// `len` bytes were taken by the writer.
    pub(crate) fn release(&self, len: usize) {
        let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::outbound_sender::budgeted_primary_channel;
    use bytes::BytesMut;
    use futures::StreamExt;

    #[test]
    fn a_budget_admits_up_to_its_limit_and_nothing_after() {
        let budget = OutboundBudget::new(10);
        assert!(budget.admit(6));
        assert!(budget.admit(4));
        assert!(!budget.admit(1));
        budget.release(10);
        assert!(!budget.admit(1), "once exhausted, it stays exhausted");
    }

    #[citadel_io::tokio::test]
    async fn a_stream_whose_peer_stops_reading_holds_at_most_its_budget_and_then_ends() {
        let (tx, mut rx) = budgeted_primary_channel(1_000);
        let packet = || BytesMut::from(&[0u8; 100][..]);
        // Ten fit; the rest are refused and nothing more is queued.
        let sent = (0..10_000)
            .filter(|_| tx.unbounded_send(packet()).is_ok())
            .count();
        assert_eq!(sent, 10);
        assert_eq!(tx.budget().map(|b| b.queued()), Some(1_000));
        // The writer's receiver ends instead of draining a stream that is over.
        assert!(rx.0.next().await.is_none());
    }

    #[citadel_io::tokio::test]
    async fn a_reading_peer_never_reaches_the_budget() {
        let (tx, mut rx) = budgeted_primary_channel(1_000);
        for _ in 0..10_000 {
            tx.unbounded_send(BytesMut::from(&[0u8; 100][..])).unwrap();
            assert!(rx.0.next().await.is_some());
        }
        assert_eq!(tx.budget().map(|b| b.queued()), Some(0));
    }
}
