//! Raw hole-punched `UdpSocket` transport (C2S UDP when the primary stream is not QUIC).
//!
//! The send half writes straight from the caller's `Bytes` with `poll_send_to` — no framing
//! codec, no intermediate write buffer, no per-datagram copy. The recv half reuses one
//! `CODEC_BUFFER_CAPACITY` scratch buffer and hands out `split_to(n)` slices.

use super::UdpSplittable;
use crate::constants::CODEC_BUFFER_CAPACITY;
use crate::proto::peer::p2p_conn_handler::generic_error;
use bytes::{Bytes, BytesMut};
use citadel_io::tokio::net::UdpSocket;
use citadel_io::NetworkError;
use futures::{Sink, Stream};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

impl UdpSplittable for RawUdpSocketConnector {
    type Sink = RawUdpSocketSink;
    type Stream = RawUdpSocketStream;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
        (self.sink, self.stream)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr
            .as_ref()
            .map(|r| *r)
            .map_err(|err| generic_error(format!("{err:?}")))
    }
}

pub struct RawUdpSocketConnector {
    sink: RawUdpSocketSink,
    stream: RawUdpSocketStream,
    local_addr: std::io::Result<SocketAddr>,
}

impl RawUdpSocketConnector {
    pub fn new(socket: UdpSocket, peer_addr: SocketAddr) -> Self {
        let local_addr = socket.local_addr();

        // Attempt the io_uring recv backend first (it needs to dup the fd). On success it is the
        // sole reader; the send half always stays on the standard path.
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        let io_uring_recv = citadel_io::IoUringUdpReceiver::try_spawn(&socket);

        let socket = Arc::new(socket);

        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        let stream = match io_uring_recv {
            Some(recv) => {
                log::trace!(target: "citadel", "Raw UDP recv using io_uring backend");
                RawUdpSocketStream::IoUring(recv)
            }
            None => RawUdpSocketStream::Standard(StandardRecv::new(socket.clone())),
        };
        #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
        let stream = RawUdpSocketStream::Standard(StandardRecv::new(socket.clone()));

        Self {
            sink: RawUdpSocketSink {
                socket,
                peer_addr,
                pending: None,
            },
            stream,
            local_addr,
        }
    }

    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.sink.peer_addr
    }
}

pub(crate) struct RawUdpSocketSink {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    pending: Option<Bytes>,
}

impl Sink<Bytes> for RawUdpSocketSink {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        debug_assert!(
            self.pending.is_none(),
            "start_send called before poll_ready"
        );
        self.pending = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        if let Some(item) = this.pending.as_ref() {
            let res = ready!(this.socket.poll_send_to(cx, item, this.peer_addr));
            this.pending = None;
            res.map_err(|err| NetworkError::generic(err.to_string()))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

pub(crate) struct StandardRecv {
    socket: Arc<UdpSocket>,
    scratch: BytesMut,
}

impl StandardRecv {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            scratch: BytesMut::zeroed(CODEC_BUFFER_CAPACITY),
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::io::Result<(BytesMut, SocketAddr)>>> {
        // Keep a fully-initialized scratch window. After `split_to` the window shrinks; refill the
        // tail in place when the allocation is still ours, otherwise start a fresh one (no copy).
        if self.scratch.len() < CODEC_BUFFER_CAPACITY {
            if self.scratch.capacity() < CODEC_BUFFER_CAPACITY {
                self.scratch = BytesMut::zeroed(CODEC_BUFFER_CAPACITY);
            } else {
                self.scratch.resize(CODEC_BUFFER_CAPACITY, 0);
            }
        }
        let mut read_buf = citadel_io::tokio::io::ReadBuf::new(&mut self.scratch[..]);
        let addr = match ready!(self.socket.poll_recv_from(cx, &mut read_buf)) {
            Ok(addr) => addr,
            Err(err) => return Poll::Ready(Some(Err(err))),
        };
        let n = read_buf.filled().len();
        Poll::Ready(Some(Ok((self.scratch.split_to(n), addr))))
    }
}

// Inbound recv half. Standard tokio path by default; on Linux with the `io-uring` feature and a
// successful ring init, the io_uring backend (in citadel_io) drives recv instead.
pub(crate) enum RawUdpSocketStream {
    Standard(StandardRecv),
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    IoUring(citadel_io::IoUringUdpReceiver),
}

impl Stream for RawUdpSocketStream {
    type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut *self {
            RawUdpSocketStream::Standard(recv) => recv.poll_recv(cx),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            RawUdpSocketStream::IoUring(recv) => recv.poll_recv(cx),
        }
    }
}
