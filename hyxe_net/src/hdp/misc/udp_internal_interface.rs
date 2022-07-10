use crate::constants::CODEC_BUFFER_CAPACITY;
use crate::error::NetworkError;
use crate::functional::PairMap;
use crate::hdp::codec::BytesCodec;
use crate::hdp::peer::p2p_conn_handler::generic_error;
use crate::macros::ContextRequirements;
use bytes::{Bytes, BytesMut};
use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream, StreamExt};
use hyxe_wire::exports::{Connection, NewConnection};
use hyxe_wire::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

pub(crate) trait UdpSink:
    Sink<Bytes, Error = NetworkError> + Unpin + ContextRequirements
{
}
impl<T: Sink<Bytes, Error = NetworkError> + Unpin + ContextRequirements> UdpSink for T {}

pub(crate) trait UdpStream:
    Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin + ContextRequirements
{
}
impl<
        T: Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin + ContextRequirements,
    > UdpStream for T
{
}

pub(crate) trait UdpSplittable: ContextRequirements {
    type Sink: UdpSink;
    type Stream: UdpStream;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream);
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

pub(crate) enum UdpSplittableTypes {
    QUIC(QuicUdpSocketConnector),
    Raw(RawUdpSocketConnector),
}

impl UdpSplittableTypes {
    pub fn split(self) -> (Box<dyn UdpSink>, Box<dyn UdpStream>) {
        match self {
            Self::QUIC(quic) => quic
                .split_sink_stream()
                .map_left(|r| Box::new(r) as _)
                .map_right(|r| Box::new(r) as _),
            Self::Raw(raw) => raw
                .split_sink_stream()
                .map_left(|r| Box::new(r) as _)
                .map_right(|r| Box::new(r) as _),
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::QUIC(quic) => quic.local_addr(),
            Self::Raw(raw) => raw.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> TargettedSocketAddr {
        match self {
            Self::QUIC(quic) => TargettedSocketAddr::new_invariant(quic.sink.sink.remote_address()),
            Self::Raw(raw) => TargettedSocketAddr::new_invariant(raw.sink.peer_addr),
        }
    }

    /// QUIC automatically handles keep alives, RAW UDP does not
    pub(crate) fn needs_manual_ka(&self) -> bool {
        matches!(self, UdpSplittableTypes::Raw(..))
    }
}

impl UdpSplittable for QuicUdpSocketConnector {
    type Sink = QuicUdpSendHalf;
    type Stream = QuicUdpRecvHalf;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
        let (sink, stream) = (self.sink, self.stream);
        (sink, stream)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub(crate) struct QuicUdpSocketConnector {
    sink: QuicUdpSendHalf,
    stream: QuicUdpRecvHalf,
    local_addr: SocketAddr,
}

impl QuicUdpSocketConnector {
    pub fn new(conn: NewConnection, local_addr: SocketAddr) -> Self {
        Self {
            sink: QuicUdpSendHalf {
                sink: conn.connection.clone(),
            },
            stream: QuicUdpRecvHalf { stream: conn },
            local_addr,
        }
    }
}

pub(crate) struct QuicUdpSendHalf {
    sink: Connection,
}

pub(crate) struct QuicUdpRecvHalf {
    stream: NewConnection,
}

impl Sink<Bytes> for QuicUdpSendHalf {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.sink
            .send_datagram(item)
            .map_err(|err| NetworkError::Generic(format!("{:?}", err)))
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
        let addr = self.stream.connection.remote_address();
        // TODO: Upon quinn PR resolution, this will receive a BytesMut instead of a Bytes and we'll no longer need to copy
        Pin::new(&mut self.stream.datagrams)
            .poll_next(cx)
            .map_err(|err| generic_error(err))
            .map_ok(|r| (BytesMut::from(&r[..]), addr))
    }
}

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
            .map_err(|err| generic_error(format!("{:?}", err)))
    }
}

pub(crate) struct RawUdpSocketConnector {
    sink: RawUdpSocketSink,
    stream: RawUdpSocketStream,
    local_addr: std::io::Result<SocketAddr>,
}

impl RawUdpSocketConnector {
    pub fn new(socket: UdpSocket, peer_addr: SocketAddr) -> Self {
        let local_addr = socket.local_addr();
        let framed = UdpFramed::new(
            socket,
            super::super::codec::BytesCodec::new(CODEC_BUFFER_CAPACITY),
        );
        let (sink, stream) = framed.split();

        Self {
            sink: RawUdpSocketSink { sink, peer_addr },
            stream: RawUdpSocketStream { stream },
            local_addr,
        }
    }
}

pub(crate) struct RawUdpSocketSink {
    sink: SplitSink<UdpFramed<BytesCodec>, (Bytes, SocketAddr)>,
    peer_addr: SocketAddr,
}

pub(crate) struct RawUdpSocketStream {
    stream: SplitStream<UdpFramed<BytesCodec>>,
}

impl Sink<Bytes> for RawUdpSocketSink {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_ready(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let addr = self.peer_addr;
        Pin::new(&mut self.sink)
            .start_send((item, addr))
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

impl Stream for RawUdpSocketStream {
    type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream)
            .poll_next(cx)
            .map_err(|err| generic_error(err))
    }
}
