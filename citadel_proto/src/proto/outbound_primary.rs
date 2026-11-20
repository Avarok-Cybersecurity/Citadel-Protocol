//! The outbound queue of one stream: a session's primary stream, a direct P2P stream, or a
//! node-local relay. A peer-facing stream's queue carries an [`OutboundBudget`].

use crate::proto::outbound_budget::OutboundBudget;
use crate::proto::outbound_sender::{
    unbounded, OutboundPacket, SendError, UnboundedReceiver, UnboundedSender,
};
use crate::proto::outbound_total::OutboundTotal;
use bytes::{Bytes, BytesMut};
use futures::task::{Context, Poll};
use std::pin::Pin;
use std::sync::Arc;

/// A stream's outbound queue: with a budget (see [`OutboundBudget`]) for a peer-facing stream,
/// without one for a node-local queue.
#[derive(Clone)]
pub struct OutboundPrimaryStreamSender(
    UnboundedSender<OutboundPacket>,
    Option<Arc<OutboundBudget>>,
);

impl OutboundPrimaryStreamSender {
    /// True once the stream's writer is gone: nothing sent now would leave.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.0 .0.is_closed()
    }

    #[inline]
    pub fn unbounded_send(&self, item: bytes::BytesMut) -> Result<(), SendError<OutboundPacket>> {
        self.send(OutboundPacket::Contiguous(item))
    }

    /// Queue a packet whose header and payload are sent as two buffers via vectored I/O,
    /// eliminating the copy that materializing a single contiguous packet would require.
    #[inline]
    pub fn unbounded_send_split(
        &self,
        header: BytesMut,
        payload: Bytes,
    ) -> Result<(), SendError<OutboundPacket>> {
        self.send(OutboundPacket::Split { header, payload })
    }

    /// Queue a flush-barrier: the writer flushes everything queued before this marker, then signals
    /// `ack`. See [`OutboundPacket::Flush`].
    #[inline]
    fn send_flush(
        &self,
        ack: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), SendError<OutboundPacket>> {
        self.send(OutboundPacket::Flush(ack))
    }

    /// Queue `packet`, then wait until the writer has flushed it to the socket. A session that
    /// ends once it has replied awaits this before it reads as ending: from then on its tasks
    /// may stop and drop the writer with the reply still queued. Resolves early when the writer
    /// is gone, since nothing queued would leave then.
    pub async fn send_and_flush(&self, packet: BytesMut) -> Result<(), SendError<OutboundPacket>> {
        let (ack_tx, ack_rx) = citadel_io::tokio::sync::oneshot::channel();
        self.unbounded_send(packet)?;
        self.send_flush(ack_tx)?;
        // Err: the writer dropped the barrier unflushed, so its stream has ended.
        let _ = ack_rx.await;
        Ok(())
    }

    fn send(&self, packet: OutboundPacket) -> Result<(), SendError<OutboundPacket>> {
        let len = packet.body_len();
        if let Some(budget) = &self.1 {
            if !budget.admit(len) {
                return Err(SendError(packet));
            }
        }
        self.0.unbounded_send(packet).inspect_err(|_| {
            // The writer is gone: these bytes will never be taken.
            if let Some(budget) = &self.1 {
                budget.release(len);
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn budget(&self) -> Option<&OutboundBudget> {
        self.1.as_deref()
    }
}

impl From<UnboundedSender<OutboundPacket>> for OutboundPrimaryStreamSender {
    fn from(inner: UnboundedSender<OutboundPacket>) -> Self {
        Self(inner, None)
    }
}

/// The channel of a peer-facing stream, whose queue holds at most `limit` bytes, and whose bytes
/// also count against the node's `total`, when it has one.
pub(crate) fn budgeted_primary_channel(
    limit: usize,
    total: Option<Arc<OutboundTotal>>,
) -> (OutboundPrimaryStreamSender, OutboundPrimaryStreamReceiver) {
    let (tx, rx) = unbounded();
    let budget = match total {
        Some(total) => OutboundBudget::within(limit, total),
        None => OutboundBudget::new(limit),
    };
    (
        OutboundPrimaryStreamSender(tx, Some(budget.clone())),
        OutboundPrimaryStreamReceiver(BudgetedReceiver {
            inner: citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(rx),
            budget: Some(budget),
        }),
    )
}

pub struct OutboundPrimaryStreamReceiver(pub BudgetedReceiver);

impl From<UnboundedReceiver<OutboundPacket>> for OutboundPrimaryStreamReceiver {
    fn from(inner: UnboundedReceiver<OutboundPacket>) -> Self {
        Self(BudgetedReceiver {
            inner: citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(inner),
            budget: None,
        })
    }
}

/// The writer's end of a stream's queue. It returns each packet's bytes to the budget as it
/// takes them, and ends once the budget is exhausted.
pub struct BudgetedReceiver {
    inner: citadel_io::tokio_stream::wrappers::UnboundedReceiverStream<OutboundPacket>,
    budget: Option<Arc<OutboundBudget>>,
}

impl futures::Stream for BudgetedReceiver {
    type Item = OutboundPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.budget.as_ref().is_some_and(|b| b.is_exhausted()) {
            return Poll::Ready(None);
        }
        let next = Pin::new(&mut self.inner).poll_next(cx);
        if let (Poll::Ready(Some(packet)), Some(budget)) = (&next, &self.budget) {
            budget.release(packet.body_len());
        }
        next
    }
}

/// A writer's end that goes returns what is still queued to its budget, which a node-wide total
/// would otherwise go on counting.
impl Drop for BudgetedReceiver {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            self.inner.close();
            while let Ok(packet) = self.inner.as_mut().try_recv() {
                budget.release(packet.body_len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, StreamExt};

    fn reply() -> BytesMut {
        BytesMut::from(&b"final reply"[..])
    }

    #[citadel_io::tokio::test]
    async fn a_reply_counts_as_sent_only_once_the_writer_has_flushed_it() {
        let (tx, mut rx) = budgeted_primary_channel(1_000, None);
        let mut sent = Box::pin(tx.send_and_flush(reply()));
        assert!((&mut sent).now_or_never().is_none(), "queued is not sent");

        let Some(OutboundPacket::Contiguous(packet)) = rx.0.next().await else {
            panic!("the reply was not queued first");
        };
        assert_eq!(&packet[..], &reply()[..]);
        assert!((&mut sent).now_or_never().is_none(), "taken is not flushed");

        let Some(OutboundPacket::Flush(ack)) = rx.0.next().await else {
            panic!("no flush-barrier followed the reply");
        };
        assert!(
            (&mut sent).now_or_never().is_none(),
            "written is not flushed"
        );
        ack.send(()).unwrap();
        assert!(matches!(sent.now_or_never(), Some(Ok(()))));
    }

    #[citadel_io::tokio::test]
    async fn a_writer_that_ends_before_flushing_does_not_hold_the_reply_wait() {
        let (tx, mut rx) = budgeted_primary_channel(1_000, None);
        let mut sent = Box::pin(tx.send_and_flush(reply()));
        assert!((&mut sent).now_or_never().is_none());
        assert!(rx.0.next().await.is_some());
        drop(rx);
        assert!(matches!(sent.now_or_never(), Some(Ok(()))));
    }

    #[citadel_io::tokio::test]
    async fn a_reply_to_a_writer_already_gone_is_refused() {
        let (tx, rx) = budgeted_primary_channel(1_000, None);
        drop(rx);
        assert!(tx.send_and_flush(reply()).await.is_err());
    }
}
