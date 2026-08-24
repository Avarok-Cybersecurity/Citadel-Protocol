//! QUIC unreliable-datagram UDP transport (all P2P, and C2S when the primary stream is QUIC).

use super::UdpSplittable;
use bytes::{Bytes, BytesMut};
use citadel_io::{error, ErrorCode, NetworkError};
use citadel_wire::exports::Connection;
use futures::{Sink, Stream};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

impl UdpSplittable for QuicUdpSocketConnector {
    type Sink = QuicUdpSendHalf;
    type Stream = QuicUdpRecvHalf;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
        (self.sink, self.stream)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub struct QuicUdpSocketConnector {
    sink: QuicUdpSendHalf,
    stream: QuicUdpRecvHalf,
    local_addr: SocketAddr,
}

impl QuicUdpSocketConnector {
    /// Largest datagram the peer currently accepts, if datagrams are enabled on this connection.
    pub fn max_datagram_len(&self) -> Option<usize> {
        self.sink.sink.max_datagram_size()
    }

    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.sink.sink.remote_address()
    }

    pub fn new(conn: Connection, local_addr: SocketAddr) -> Self {
        let addr = conn.remote_address();
        let conn_stream = conn.clone();
        let receiver = Box::pin(async_stream::try_stream! {
            loop {
                yield conn_stream.read_datagram()
                .await
                .map(|packet| (BytesMut::from(&packet[..]), addr))
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            }
        });

        Self {
            sink: QuicUdpSendHalf { sink: conn },
            stream: QuicUdpRecvHalf { receiver },
            local_addr,
        }
    }
}

pub(crate) struct QuicUdpSendHalf {
    sink: Connection,
}

pub(crate) struct QuicUdpRecvHalf {
    receiver: ReceiverStream,
}

type ReceiverStream =
    Pin<Box<dyn Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Send + 'static>>;

impl Sink<Bytes> for QuicUdpSendHalf {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        use citadel_wire::exports::SendDatagramError;
        let len = item.len();
        self.sink.send_datagram(item).map_err(|err| match err {
            SendDatagramError::TooLarge => error!(
                ErrorCode::UdpDatagramTooLarge,
                len,
                self.sink.max_datagram_size().unwrap_or(0)
            ),
            other => NetworkError::generic(format!("{other:?}")),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for QuicUdpRecvHalf {
    type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.as_mut().poll_next(cx)
    }
}
