//use futures::channel::mpsc::{UnboundedSender, SendError, UnboundedReceiver, TrySendError};
pub use tokio::sync::mpsc::{UnboundedSender as UnboundedSenderInner, UnboundedReceiver, error::SendError, error::TrySendError, Sender, Receiver};
use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::Sink;
use futures::task::{Context, Poll};
use std::pin::Pin;
use crate::error::NetworkError;


pub struct UnboundedSender<T>(pub(crate) UnboundedSenderInner<T>);

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (UnboundedSender(tx), rx)
}

impl<T> UnboundedSender<T> {
    #[inline]
    pub fn unbounded_send(&self, item: T) -> Result<(), SendError<T>> {
        self.0.send(item)
    }
}

pub fn channel<T>(len: usize) -> (Sender<T>, Receiver<T>) {
    tokio::sync::mpsc::channel(len)
}

#[derive(Clone)]
pub struct OutboundTcpSender(UnboundedSender<bytes::BytesMut>);

impl OutboundTcpSender {
    #[inline]
    pub fn unbounded_send(&self, item: bytes::BytesMut) -> Result<(), SendError<BytesMut>> {
        self.0.unbounded_send(item)
    }
}

impl From<UnboundedSender<bytes::BytesMut>> for OutboundTcpSender {
    fn from(inner: UnboundedSender<BytesMut>) -> Self {
        Self(inner)
    }
}

pub struct OutboundTcpReceiver(pub tokio_stream::wrappers::UnboundedReceiverStream<bytes::BytesMut>);

impl From<UnboundedReceiver<bytes::BytesMut>> for OutboundTcpReceiver {
    fn from(inner: UnboundedReceiver<BytesMut>) -> Self {
        Self(tokio_stream::wrappers::UnboundedReceiverStream::new(inner))
    }
}

/// For keeping the firewall open
pub static KEEP_ALIVE: Bytes = Bytes::from_static(b"ACK");

#[derive(Clone)]
pub struct OutboundUdpSender {
    sender: UnboundedSender<(usize, BytesMut)>,
    total_local_ports: usize,
    rolling_idx: Arc<AtomicUsize>
}

impl OutboundUdpSender {
    pub fn new(sender: UnboundedSender<(usize, BytesMut)>, total_local_ports: usize) -> Self {
        let rolling_idx = Arc::new(AtomicUsize::new(0));
        Self { sender, total_local_ports, rolling_idx}
    }

    #[inline]
    pub fn send_with_idx(&self, idx: usize, packet: BytesMut) -> bool {
        self.sender.unbounded_send((idx, packet)).is_ok()
    }

    /// Automatically handles the port rotations
    ///
    /// returns false if the channel is closed, true is success
    pub fn unbounded_send(&self, packet: BytesMut) -> bool {
        let idx = self.get_and_increment_idx();
        self.send_with_idx(idx, packet)
    }

    pub fn send_keep_alive_through_all(&self) -> bool {
        for idx in 0..self.total_local_ports {
            if !self.send_with_idx(idx, BytesMut::from(&KEEP_ALIVE[..])) {
                return false;
            }
        }

        true
    }

    // Get and increments value (mod total_local_ports)
    fn get_and_increment_idx(&self) -> usize {
        let total_local_ports = self.total_local_ports;
        let prev = self.rolling_idx.load(Ordering::Relaxed);
        let next = (prev + 1) % total_local_ports;
        self.rolling_idx.store(next, Ordering::Relaxed);
        prev
    }
}


impl Sink<BytesMut> for OutboundUdpSender {
    type Error = SendError<(usize, BytesMut)>;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
        let idx = self.get_and_increment_idx();
        self.sender.unbounded_send((idx, item))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/*
impl<T> Sink<T> for UnboundedSender<T> {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        Pin::new(&mut self.0).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}*/

/// As asynchronous channel meant to rate-limit input
pub struct BoundedSender<T>(futures::channel::mpsc::Sender<T>);

pub type BoundedReceiver<T> = futures::channel::mpsc::Receiver<T>;

impl<T> BoundedSender<T> {
    /// Creates a new bounded channel
    pub fn new(limit: usize) -> (BoundedSender<T>, futures::channel::mpsc::Receiver<T>) {
        let (tx, rx) = futures::channel::mpsc::channel(limit);
        (Self(tx), rx)
    }
}

impl<T> Clone for BoundedSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Sink<T> for BoundedSender<T> {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <futures::channel::mpsc::Sender<T> as Sink<T>>::poll_ready(Pin::new(&mut self.0), cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        <futures::channel::mpsc::Sender<T> as Sink<T>>::start_send(Pin::new(&mut self.0), item)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <futures::channel::mpsc::Sender<T> as Sink<T>>::poll_flush(Pin::new(&mut self.0), cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <futures::channel::mpsc::Sender<T> as Sink<T>>::poll_close(Pin::new(&mut self.0), cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

impl<T> Sink<T> for UnboundedSender<T> {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.0.is_closed() {
            Poll::Ready(Err(NetworkError::InternalError("Channel closed")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.0.send(item).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}