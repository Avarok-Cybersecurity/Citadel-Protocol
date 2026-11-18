//! The outbound queue of one stream: a session's primary stream, a direct P2P stream, or a
//! node-local relay. A peer-facing stream's queue carries an [`OutboundBudget`].

use crate::proto::outbound_budget::OutboundBudget;
use crate::proto::outbound_sender::{
    unbounded, OutboundPacket, SendError, UnboundedReceiver, UnboundedSender,
};
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
    pub fn send_flush(
        &self,
        ack: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), SendError<OutboundPacket>> {
        self.send(OutboundPacket::Flush(ack))
    }

    fn send(&self, packet: OutboundPacket) -> Result<(), SendError<OutboundPacket>> {
        if let Some(budget) = &self.1 {
            if !budget.admit(packet.body_len()) {
                return Err(SendError(packet));
            }
        }
        self.0.unbounded_send(packet)
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

/// The channel of a peer-facing stream, whose queue holds at most `limit` bytes.
pub(crate) fn budgeted_primary_channel(
    limit: usize,
) -> (OutboundPrimaryStreamSender, OutboundPrimaryStreamReceiver) {
    let (tx, rx) = unbounded();
    let budget = Arc::new(OutboundBudget::new(limit));
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
