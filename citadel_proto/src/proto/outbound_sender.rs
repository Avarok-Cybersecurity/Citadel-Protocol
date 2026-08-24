//! # Citadel Protocol Outbound Message Handling
//!
//! This module provides functionality for sending outbound messages in the Citadel Protocol.
//! It implements various types of message senders optimized for different use cases,
//! including bounded and unbounded channels, UDP and TCP streams.
//!
//! ## Features
//!
//! - **Multiple Channel Types**:
//!   - Unbounded channels for high-throughput scenarios
//!   - Bounded channels for rate-limiting and backpressure
//!   - UDP-specific senders for datagram-based communication
//!
//! - **Stream Management**:
//!   - Primary stream handling for reliable TCP communication
//!   - UDP stream handling with keep-alive support
//!   - Automatic stream cleanup and resource management
//!
//! - **Error Handling**:
//!   - Comprehensive error types for different failure scenarios
//!   - Graceful handling of connection issues
//!   - Automatic retry mechanisms
//!
//! - **Performance Optimizations**:
//!   - Zero-copy buffer management
//!   - Efficient async/await support
//!   - Minimal allocation overhead
//!
//! ## Components
//!
//! - **UnboundedSender**: High-throughput channel without backpressure
//! - **BoundedSender**: Rate-limited channel with backpressure
//! - **OutboundPrimaryStreamSender**: TCP stream management
//! - **OutboundUdpSender**: UDP datagram handling with keep-alive

use crate::error::NetworkError;
pub use crate::proto::outbound_udp_sender::{OutboundUdpSender, UdpQueueItem};
use bytes::{Bytes, BytesMut};
pub use citadel_io::tokio::sync::mpsc::{
    error::SendError, Receiver, Sender, UnboundedReceiver, UnboundedSender as UnboundedSenderInner,
};
use futures::task::{Context, Poll};
use futures::Sink;
use std::pin::Pin;

pub struct UnboundedSender<T>(pub(crate) UnboundedSenderInner<T>);

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
    (UnboundedSender(tx), rx)
}

impl<T> UnboundedSender<T> {
    #[inline]
    pub fn unbounded_send(&self, item: T) -> Result<(), SendError<T>> {
        self.0.send(item)
    }
}

pub fn channel<T>(len: usize) -> (Sender<T>, Receiver<T>) {
    citadel_io::tokio::sync::mpsc::channel(len)
}

/// A unit of work queued for the primary outbound stream.
///
/// `Contiguous` carries a single `[header | payload]` buffer (control, message, and
/// single-packet paths). `Split` carries the header and the (shared) ciphertext payload
/// as two independent buffers so the wire writer can emit them with vectored I/O,
/// avoiding the per-chunk copy that concatenating them would require. In both cases the
/// on-wire bytes are identical to a single `[length | header | payload]` frame.
#[derive(Debug)]
pub enum OutboundPacket {
    Contiguous(BytesMut),
    Split {
        header: BytesMut,
        payload: Bytes,
    },
    /// A flush-barrier (carries no wire bytes): the writer flushes everything queued before it, then
    /// signals `ack`. Used on the graceful-disconnect path to deterministically wait for the FINAL
    /// packet to reach the socket BEFORE the session ends (and the writer is dropped), replacing a
    /// fixed sleep. Best-effort on the writer side — a flush failure is swallowed (still acks), so it
    /// can never resolve the writer task with an error / change the session exit reason.
    Flush(citadel_io::tokio::sync::oneshot::Sender<()>),
}

impl OutboundPacket {
    /// Total on-wire body length (the value written into the length-delimited frame prefix).
    #[inline]
    pub fn body_len(&self) -> usize {
        match self {
            OutboundPacket::Contiguous(buf) => buf.len(),
            OutboundPacket::Split { header, payload } => header.len() + payload.len(),
            OutboundPacket::Flush(_) => 0,
        }
    }
}

#[derive(Clone)]
pub struct OutboundPrimaryStreamSender(UnboundedSender<OutboundPacket>);

impl OutboundPrimaryStreamSender {
    #[inline]
    pub fn unbounded_send(&self, item: bytes::BytesMut) -> Result<(), SendError<OutboundPacket>> {
        self.0.unbounded_send(OutboundPacket::Contiguous(item))
    }

    /// Queue a packet whose header and payload are sent as two buffers via vectored I/O,
    /// eliminating the copy that materializing a single contiguous packet would require.
    #[inline]
    pub fn unbounded_send_split(
        &self,
        header: BytesMut,
        payload: Bytes,
    ) -> Result<(), SendError<OutboundPacket>> {
        self.0
            .unbounded_send(OutboundPacket::Split { header, payload })
    }

    /// Queue a flush-barrier: the writer flushes everything queued before this marker, then signals
    /// `ack`. See [`OutboundPacket::Flush`].
    #[inline]
    pub fn send_flush(
        &self,
        ack: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), SendError<OutboundPacket>> {
        self.0.unbounded_send(OutboundPacket::Flush(ack))
    }
}

impl From<UnboundedSender<OutboundPacket>> for OutboundPrimaryStreamSender {
    fn from(inner: UnboundedSender<OutboundPacket>) -> Self {
        Self(inner)
    }
}

pub struct OutboundPrimaryStreamReceiver(
    pub citadel_io::tokio_stream::wrappers::UnboundedReceiverStream<OutboundPacket>,
);

impl From<UnboundedReceiver<OutboundPacket>> for OutboundPrimaryStreamReceiver {
    fn from(inner: UnboundedReceiver<OutboundPacket>) -> Self {
        Self(citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(inner))
    }
}

/// As asynchronous channel meant to rate-limit input
pub struct BoundedSender<T>(citadel_io::tokio::sync::mpsc::Sender<T>);

pub type BoundedReceiver<T> = citadel_io::tokio::sync::mpsc::Receiver<T>;

impl<T> BoundedSender<T> {
    /// Creates a new bounded channel
    pub fn new(limit: usize) -> (BoundedSender<T>, BoundedReceiver<T>) {
        let (tx, rx) = citadel_io::tokio::sync::mpsc::channel(limit);
        (Self(tx), rx)
    }

    /// Attempts to send a value through the stream non-blocking and synchronously
    pub fn try_send(
        &self,
        t: T,
    ) -> Result<(), citadel_io::tokio::sync::mpsc::error::TrySendError<T>> {
        self.0.try_send(t)
    }

    /// Sends a value through the channel
    pub async fn send(
        &self,
        t: T,
    ) -> Result<(), citadel_io::tokio::sync::mpsc::error::SendError<T>> {
        self.0.send(t).await
    }
}

impl<T> Clone for BoundedSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Sink<T> for UnboundedSender<T> {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.0.is_closed() {
            Poll::Ready(Err(NetworkError::internal("Channel tx closed")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.0
            .send(item)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
