//! Datagram sink/source abstractions that decouple the media sender/receiver
//! from the concrete Citadel channel halves.
use bytes::BytesMut;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::ErrorCode;

use citadel_proto::prelude::{
    NetworkError, OutboundUdpSender, PeerChannelSendHalf, Ratchet, SecBuffer,
};
use futures::{SinkExt, Stream};
use std::pin::Pin;

/// Which path media fragments take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaTransportKind {
    /// Fragments over the session UDP channel (lossy, unordered).
    Unreliable,
    /// Fragments over the ordered-reliable channel (UDP unavailable).
    Reliable,
}

/// Synchronous, never-blocking datagram sink. Mirrors
/// `OutboundUdpSender::unbounded_send`: a failure is terminal for that datagram.
pub trait MediaDatagramSink: Send + Sync + 'static {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError>;
}

impl MediaDatagramSink for OutboundUdpSender {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError> {
        self.unbounded_send(buf)
    }
}

/// Stream of inbound datagrams (one `SecBuffer` per wire message).
pub trait MediaDatagramSource: Stream<Item = SecBuffer> + Send + Sync + 'static {}
impl<S: Stream<Item = SecBuffer> + Send + Sync + 'static> MediaDatagramSource for S {}

pub(crate) type BoxedSink = Box<dyn MediaDatagramSink>;
pub(crate) type BoxedSource = Pin<Box<dyn MediaDatagramSource>>;

/// Sync façade over the ordered-reliable channel: datagrams are queued on an
/// unbounded channel and a pump task forwards them through
/// `PeerChannelSendHalf::into_sink`. Cloning shares the same pump.
#[derive(Debug, Clone)]
pub struct ReliableSink {
    tx: UnboundedSender<BytesMut>,
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
    pub fn pair() -> (Self, UnboundedReceiver<BytesMut>) {
        let (tx, rx) = unbounded_channel();
        (Self { tx }, rx)
    }

    /// Forwards every queued datagram until the queue or the channel closes.
    pub async fn pump<R: Ratchet>(
        mut rx: UnboundedReceiver<BytesMut>,
        send_half: PeerChannelSendHalf<R>,
    ) {
        let mut sink = send_half.into_sink();
        while let Some(buf) = rx.recv().await {
            if let Err(err) = sink.send(buf.freeze()).await {
                log::warn!(target: "citadel", "media reliable pump ended: {err}");
                return;
            }
        }
    }
}

impl MediaDatagramSink for ReliableSink {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError> {
        self.tx.send(buf).map_err(|_| {
            citadel_io::error!(ErrorCode::MediaTransportClosed, "reliable pump is gone")
        })
    }
}
