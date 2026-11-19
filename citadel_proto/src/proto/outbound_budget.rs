//! How many bytes may wait in a peer-facing stream's outbound queue.
//!
//! A stream's queue grows only as fast as its peer reads, so a peer that stops reading would
//! otherwise grow it without bound. Each peer-facing stream (a session's primary stream, and a
//! direct P2P stream) carries an [`OutboundBudget`]: once the bytes queued and not yet taken by
//! the writer would exceed it, the stream is over. Every later send fails, and the writer's
//! receiver ends, which ends the stream and the session it carries.
//!
//! A server's streams also count against one node-wide total (see
//! [`OutboundTotal`](crate::proto::outbound_total::OutboundTotal)): a send that would take the
//! node past it ends the stream holding the most, so all the streams together hold at most that
//! much, and a stream whose peer reads is not ended for one whose peer does not.

use crate::proto::outbound_total::OutboundTotal;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// The most bytes a peer-facing stream holds queued for its writer. Packets reach the queue
/// paced by what the peer acknowledges: a file transfer keeps about one and a half
/// 10 MiB groups unacknowledged, so this admits more than a dozen concurrent transfers to one
/// slow peer, while bounding what a peer that has stopped reading can make this node hold.
pub(crate) const MAX_QUEUED_OUTBOUND_BYTES: usize = 256 * 1024 * 1024;

pub(crate) struct OutboundBudget {
    limit: usize,
    queued: AtomicUsize,
    exhausted: AtomicBool,
    /// The node-wide total this stream's bytes also count against, on a server.
    total: Option<Arc<OutboundTotal>>,
}

impl OutboundBudget {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self::unenrolled(limit, None))
    }

    /// A stream's budget of `limit` bytes, whose bytes also count against `total`.
    pub(crate) fn within(limit: usize, total: Arc<OutboundTotal>) -> Arc<Self> {
        let budget = Arc::new(Self::unenrolled(limit, Some(total.clone())));
        total.enrol(&budget);
        budget
    }

    fn unenrolled(limit: usize, total: Option<Arc<OutboundTotal>>) -> Self {
        Self {
            limit,
            queued: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
            total,
        }
    }

    /// Whether `len` more bytes may be queued. Once one send is refused, every later one is.
    pub(crate) fn admit(self: &Arc<Self>, len: usize) -> bool {
        if self.is_exhausted() {
            return false;
        }
        let queued = self.queued.fetch_add(len, Ordering::AcqRel) + len;
        if queued > self.limit {
            let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
            self.end("this stream's", self.limit);
            return false;
        }
        let Some(total) = &self.total else {
            return true;
        };
        // Each pass ends one other stream, so this ends at the latest when this stream holds the
        // most (`heaviest` never passes over it for one that holds no more).
        while !total.charge(len) {
            let heaviest = total.heaviest(self);
            if Arc::ptr_eq(&heaviest, self) {
                let _ = self.queued.fetch_sub(len, Ordering::AcqRel);
                self.end("the node's", total.limit());
                return false;
            }
            heaviest.end("the node's", total.limit());
        }
        true
    }

    /// Ends this stream: no later send is admitted, its writer's receiver ends, and what it holds
    /// no longer counts against the node's total.
    fn end(&self, whose: &str, limit: usize) {
        if self.exhausted.swap(true, Ordering::AcqRel) {
            return;
        }
        log::warn!(target: "citadel", "Outbound queue would exceed {whose} {limit} bytes; ending the stream holding the most, whose peer is not reading.");
        let held = self.queued.swap(0, Ordering::AcqRel);
        if let Some(total) = &self.total {
            total.release(held);
        }
    }

    /// `len` bytes were taken by the writer, or will never be sent. What [`Self::end`] already
    /// returned is not returned twice.
    pub(crate) fn release(&self, len: usize) {
        let mut queued = self.queued.load(Ordering::Acquire);
        let taken = loop {
            let taken = queued.min(len);
            match self.queued.compare_exchange_weak(
                queued,
                queued - taken,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break taken,
                Err(now) => queued = now,
            }
        };
        if let Some(total) = &self.total {
            total.release(taken);
        }
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Acquire)
    }

    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::outbound_sender::budgeted_primary_channel;
    use bytes::BytesMut;
    use futures::{FutureExt, StreamExt};

    fn node_total(limit: usize) -> Arc<OutboundTotal> {
        Arc::new(OutboundTotal::new(limit))
    }

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
        let (tx, mut rx) = budgeted_primary_channel(1_000, None);
        let packet = || BytesMut::from(&[0u8; 100][..]);
        // Ten fit; the rest are refused and nothing more is queued.
        let sent = (0..10_000)
            .filter(|_| tx.unbounded_send(packet()).is_ok())
            .count();
        assert_eq!(sent, 10);
        assert_eq!(tx.budget().map(|b| b.is_exhausted()), Some(true));
        // The writer's receiver ends instead of draining a stream that is over.
        assert!(rx.0.next().await.is_none());
    }

    #[citadel_io::tokio::test]
    async fn a_reading_peer_never_reaches_the_budget() {
        let (tx, mut rx) = budgeted_primary_channel(1_000, None);
        for _ in 0..10_000 {
            tx.unbounded_send(BytesMut::from(&[0u8; 100][..])).unwrap();
            assert!(rx.0.next().await.is_some());
        }
        assert_eq!(tx.budget().map(|b| b.queued()), Some(0));
    }

    #[citadel_io::tokio::test]
    async fn streams_that_stop_reading_hold_at_most_the_nodes_total_together() {
        let total = node_total(2_500);
        let mut streams: Vec<_> = (0..10)
            .map(|_| budgeted_primary_channel(1_000, Some(total.clone())))
            .collect();
        let packet = || BytesMut::from(&[0u8; 100][..]);
        for (tx, _rx) in &streams {
            for _ in 0..9 {
                let _ = tx.unbounded_send(packet());
            }
        }
        // What the writers can still take is what the node holds; an ended stream yields nothing.
        let mut held = 0;
        for (_tx, rx) in &mut streams {
            while let Some(Some(packet)) = rx.0.next().now_or_never() {
                held += packet.body_len();
            }
        }
        assert!(held <= 2_500, "ten streams held {held} bytes");
        assert!(held > 0, "every stream was ended");
        assert_eq!(total.queued(), 0);
    }

    #[citadel_io::tokio::test]
    async fn at_the_nodes_total_the_stream_holding_the_most_is_ended() {
        let total = node_total(1_000);
        let (honest, mut honest_rx) = budgeted_primary_channel(1_000, Some(total.clone()));
        let (abusive, mut abusive_rx) = budgeted_primary_channel(1_000, Some(total.clone()));
        let packet = || BytesMut::from(&[0u8; 100][..]);
        honest.unbounded_send(packet()).unwrap();
        for _ in 0..9 {
            abusive.unbounded_send(packet()).unwrap();
        }
        // The node is full; the honest stream's next send takes it past the total.
        honest
            .unbounded_send(packet())
            .expect("the stream holding the least was ended");
        assert!(abusive.unbounded_send(packet()).is_err());
        assert!(
            abusive_rx.0.next().await.is_none(),
            "the abusive stream goes on"
        );
        assert!(honest_rx.0.next().await.is_some());
        assert!(honest_rx.0.next().await.is_some());
        assert_eq!(total.queued(), 0, "the ended stream still counts");
    }

    #[citadel_io::tokio::test]
    async fn a_stream_that_ends_returns_what_it_held_to_the_total() {
        let total = node_total(1_000);
        let (tx, rx) = budgeted_primary_channel(1_000, Some(total.clone()));
        for _ in 0..5 {
            tx.unbounded_send(BytesMut::from(&[0u8; 100][..])).unwrap();
        }
        drop(rx);
        // Refused: the writer is gone, and its charge goes back too.
        assert!(tx.unbounded_send(BytesMut::from(&[0u8; 100][..])).is_err());
        assert_eq!(
            total.queued(),
            0,
            "an ended stream still counts against the total"
        );
    }
}
