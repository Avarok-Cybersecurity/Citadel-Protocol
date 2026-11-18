//! Datagram sink/source abstractions that decouple the media sender/receiver
//! from the concrete Citadel channel halves.
use bytes::BytesMut;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::{OwnedSemaphorePermit, Semaphore};
use citadel_io::ErrorCode;
use std::sync::Arc;

use citadel_proto::prelude::{
    NetworkError, OutboundUdpSender, PeerChannelSendHalf, Ratchet, SecBuffer,
};
use futures::future::BoxFuture;
use futures::{SinkExt, Stream};
use std::pin::Pin;

/// Which path media fragments take: the session UDP channel (`Unreliable`: lossy, unordered) or
/// the ordered-reliable channel (`Reliable`). One definition, the negotiation crate's, so the
/// value media agrees on in band is the value the endpoint runs on.
pub use citadel_negotiation::settings::MediaTransportKind;

/// Synchronous, never-blocking datagram sink. Mirrors
/// `OutboundUdpSender::unbounded_send`: a failure is terminal for that datagram.
pub trait MediaDatagramSink: Send + Sync + 'static {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError>;
    /// Whether `datagrams` more can be taken now. A sender that finds no room keeps its frame
    /// queued, where its queue's drop policy decides what survives congestion.
    fn has_room(&self, datagrams: usize) -> bool;
    /// Resolves once `datagrams` more can be taken.
    fn room_for(&self, datagrams: usize) -> BoxFuture<'static, ()>;
}

impl MediaDatagramSink for OutboundUdpSender {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError> {
        self.unbounded_send(buf)
    }

    /// Always: the UDP sender bounds its own queue, dropping the oldest datagram when full.
    fn has_room(&self, _datagrams: usize) -> bool {
        true
    }

    fn room_for(&self, _datagrams: usize) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}

/// Stream of inbound datagrams (one `SecBuffer` per wire message).
pub trait MediaDatagramSource: Stream<Item = SecBuffer> + Send + Sync + 'static {}
impl<S: Stream<Item = SecBuffer> + Send + Sync + 'static> MediaDatagramSource for S {}

pub(crate) type BoxedSink = Box<dyn MediaDatagramSink>;
pub(crate) type BoxedSource = Pin<Box<dyn MediaDatagramSource>>;

/// A datagram queued for the reliable pump. A media datagram holds its lane's permit until the
/// pump has forwarded it.
#[derive(Debug)]
pub struct QueuedDatagram {
    pub buf: BytesMut,
    _permit: Option<OwnedSemaphorePermit>,
}

/// Sync façade over the ordered-reliable channel: datagrams are queued, in order, for a pump
/// task that forwards them through `PeerChannelSendHalf::into_sink`. Cloning shares the same
/// pump and lane. The control lane is unbounded: it carries the caller's own control messages,
/// a handful per call. A media lane ([`Self::media_lane`]) shares the queue, so control and media
/// stay in order, but holds at most a fixed number of datagrams the pump has not yet forwarded.
#[derive(Debug, Clone)]
pub struct ReliableSink {
    tx: UnboundedSender<QueuedDatagram>,
    budget: Option<Arc<Semaphore>>,
}

impl ReliableSink {
    /// Creates the sink and spawns its pump over `send_half`.
    pub fn spawn<R: Ratchet>(send_half: PeerChannelSendHalf<R>) -> Self {
        let (sink, rx) = Self::pair();
        let pump = Self::pump(rx, send_half);
        drop(citadel_io::spawn(pump));
        sink
    }

    /// The unpumped channel pair. Exposed for tests and for callers that
    /// drive the pump themselves.
    pub fn pair() -> (Self, UnboundedReceiver<QueuedDatagram>) {
        let (tx, rx) = unbounded_channel();
        (Self { tx, budget: None }, rx)
    }

    /// A media lane on this sink's queue that holds at most `datagrams` unforwarded datagrams.
    pub fn media_lane(&self, datagrams: usize) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: Some(Arc::new(Semaphore::new(datagrams))),
        }
    }

    /// Forwards every queued datagram until the queue or the channel closes.
    pub async fn pump<R: Ratchet>(
        mut rx: UnboundedReceiver<QueuedDatagram>,
        send_half: PeerChannelSendHalf<R>,
    ) {
        let mut sink = send_half.into_sink();
        while let Some(queued) = rx.recv().await {
            // The permit, if any, is given back once the datagram is forwarded.
            if let Err(err) = sink.send(queued.buf.freeze()).await {
                log::warn!(target: "citadel", "media reliable pump ended: {err}");
                return;
            }
        }
    }
}

impl MediaDatagramSink for ReliableSink {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError> {
        let permit = match &self.budget {
            Some(budget) => Some(budget.clone().try_acquire_owned().map_err(|_| {
                citadel_io::error!(ErrorCode::MediaTransportClosed, "media lane is full")
            })?),
            None => None,
        };
        self.tx
            .send(QueuedDatagram {
                buf,
                _permit: permit,
            })
            .map_err(|_| {
                citadel_io::error!(ErrorCode::MediaTransportClosed, "reliable pump is gone")
            })
    }

    fn has_room(&self, datagrams: usize) -> bool {
        self.budget
            .as_ref()
            .is_none_or(|budget| budget.available_permits() >= datagrams)
    }

    fn room_for(&self, datagrams: usize) -> BoxFuture<'static, ()> {
        let budget = self.budget.clone();
        Box::pin(async move {
            if let Some(budget) = budget {
                let datagrams = u32::try_from(datagrams).unwrap_or(u32::MAX);
                // Taken and given straight back: this only waits for the pump to make room.
                // The semaphore is never closed, so this cannot fail.
                let _ = budget.acquire_many_owned(datagrams).await;
            }
        })
    }
}
