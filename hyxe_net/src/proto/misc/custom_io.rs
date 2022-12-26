use bytes::BytesMut;
use futures::Sink;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::Stream;

pub struct CustomClientIO<S, SK> {
    stream: S,
    sink: SK,
    peer_addr: std::io::Result<SocketAddr>,
}

pub(crate) const DUMMY_SOCKET_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

impl<S, SK> CustomClientIO<S, SK> {
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.peer_addr.clone()
    }
}

pub struct CustomServerAcceptor<Conn> {
    pub(crate) acceptor: Conn,
}

impl<S, SK, Conn: Stream<Item = CustomClientIO<S, SK>> + Unpin> Stream
    for CustomServerAcceptor<Conn>
where
    S: Stream<Item = BytesMut> + Unpin,
    SK: Sink<BytesMut> + Unpin,
{
    type Item = CustomClientIO<S, SK>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().acceptor).poll_next(cx)
    }
}

pub type ChanneledClientConnection = CustomClientIO<
    tokio::sync::mpsc::UnboundedReceiver<BytesMut>,
    tokio::sync::mpsc::UnboundedSender<BytesMut>,
>;
pub type ChanneledServerAcceptor =
    CustomServerAcceptor<tokio::sync::mpsc::UnboundedReceiver<ChanneledClientConnection>>;
