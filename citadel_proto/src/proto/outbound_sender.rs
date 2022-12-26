//use futures::channel::mpsc::{UnboundedSender, SendError, UnboundedReceiver, TrySendError};
use crate::error::NetworkError;
use crate::proto::packet::packet_flags;
use bytes::{Bytes, BytesMut};
use citadel_user::re_imports::__private::Formatter;
use futures::task::{Context, Poll};
use futures::Sink;
use std::net::SocketAddr;
use std::pin::Pin;
pub use tokio::sync::mpsc::{
    error::SendError, error::TrySendError, Receiver, Sender, UnboundedReceiver,
    UnboundedSender as UnboundedSenderInner,
};

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
pub struct OutboundPrimaryStreamSender(UnboundedSender<bytes::BytesMut>);

impl OutboundPrimaryStreamSender {
    #[inline]
    pub fn unbounded_send(&self, item: bytes::BytesMut) -> Result<(), SendError<BytesMut>> {
        self.0.unbounded_send(item)
    }
}

impl From<UnboundedSender<bytes::BytesMut>> for OutboundPrimaryStreamSender {
    fn from(inner: UnboundedSender<BytesMut>) -> Self {
        Self(inner)
    }
}

pub struct OutboundPrimaryStreamReceiver(
    pub tokio_stream::wrappers::UnboundedReceiverStream<bytes::BytesMut>,
);

impl From<UnboundedReceiver<bytes::BytesMut>> for OutboundPrimaryStreamReceiver {
    fn from(inner: UnboundedReceiver<BytesMut>) -> Self {
        Self(tokio_stream::wrappers::UnboundedReceiverStream::new(inner))
    }
}

/// For keeping the firewall open
pub const KEEP_ALIVE: Bytes = Bytes::from_static(b"KA");

#[derive(Clone)]
pub struct OutboundUdpSender {
    sender: UnboundedSender<(u8, BytesMut)>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    pub(crate) needs_manual_ka: bool,
}

impl OutboundUdpSender {
    pub fn new(
        sender: UnboundedSender<(u8, BytesMut)>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        needs_manual_ka: bool,
    ) -> Self {
        Self {
            sender,
            local_addr,
            remote_addr,
            needs_manual_ka,
        }
    }

    pub fn unbounded_send<T: Into<BytesMut>>(&self, packet: T) -> Result<(), NetworkError> {
        self.sender
            .unbounded_send((packet_flags::cmd::aux::udp::STREAM, packet.into()))
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub fn send_keep_alive(&self) -> bool {
        self.sender
            .unbounded_send((
                packet_flags::cmd::aux::udp::KEEP_ALIVE,
                BytesMut::from(&KEEP_ALIVE[..]),
            ))
            .is_ok()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Sink<BytesMut> for OutboundUdpSender {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_ready(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
        Pin::new(&mut self.sender)
            .start_send((packet_flags::cmd::aux::udp::STREAM, item))
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_close(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

impl std::fmt::Debug for OutboundUdpSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP Sender")
    }
}

/// As asynchronous channel meant to rate-limit input
pub struct BoundedSender<T>(futures::channel::mpsc::Sender<T>);

pub type BoundedReceiver<T> = futures::channel::mpsc::Receiver<T>;

impl<T> BoundedSender<T> {
    /// Creates a new bounded channel
    pub fn new(limit: usize) -> (BoundedSender<T>, futures::channel::mpsc::Receiver<T>) {
        let (tx, rx) = futures::channel::mpsc::channel(limit);
        (Self(tx), rx)
    }

    /// Attempts to send a value through the stream non-blocking and synchronously
    pub fn try_send(&mut self, t: T) -> Result<(), futures::channel::mpsc::TrySendError<T>> {
        self.0.try_send(t)
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
        self.0
            .send(item)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
