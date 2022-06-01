use tokio_util::codec::LengthDelimitedCodec;
use crate::hdp::misc::clean_shutdown::{clean_framed_shutdown, CleanShutdownSink, CleanShutdownStream};
use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncRead, ReadBuf};
use crate::macros::{ContextRequirements, SyncContextRequirements};
use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio_stream::{Stream, StreamExt};
use std::task::{Context, Poll};
use std::pin::Pin;
use std::ops::DerefMut;
use std::io::Error;
use hyxe_wire::exports::tokio_rustls::{server::TlsStream, TlsAcceptor};
use futures::{Future, TryStreamExt};
//use tokio_native_tls::native_tls::{Identity, Certificate};
use std::path::Path;
use crate::error::NetworkError;
use crate::hdp::hdp_node::TlsDomain;
use serde::{Serialize, Deserialize};
use hyxe_fs::io::SyncIO;
use hyxe_wire::exports::{SendStream, RecvStream, Endpoint, NewConnection};
use hyxe_wire::quic::{QuicNode, QuicEndpointListener};
use crate::hdp::peer::p2p_conn_handler::generic_error;
use std::fmt::Debug;
use hyxe_user::re_imports::__private::Formatter;
use hyxe_wire::tls::TLSQUICInterop;

/// Wraps a stream into a split interface for I/O that safely shuts-down the interface
/// upon drop
pub fn safe_split_stream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements>(stream: S)
    -> (CleanShutdownSink<S, LengthDelimitedCodec, Bytes>, CleanShutdownStream<S, LengthDelimitedCodec, Bytes>){
    // With access to the primary stream, we can now communicate through it from this session
    let framed = LengthDelimitedCodec::builder()
        .length_field_offset(0) // default value
        .length_field_length(4)
        .length_adjustment(0)   // default value
        // `num_skip` is not needed, the default is to skip
        .new_framed(stream);

    clean_framed_shutdown(framed)
}

#[allow(variant_size_differences)]
pub enum GenericNetworkStream {
    Tcp(TcpStream),
    Tls(hyxe_wire::exports::tokio_rustls::TlsStream<TcpStream>),
    // local addr is first addr, remote addr is final addr
    Quic(SendStream, RecvStream, Endpoint, Option<NewConnection>, SocketAddr)
}

impl Unpin for GenericNetworkStream {}

impl Debug for GenericNetworkStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let tag = match self {
            Self::Tcp(..) => "TCP",
            Self::Tls(..) => "TLS",
            Self::Quic(..) => "QUIC"
        };

        write!(f, "{}", tag)
    }
}

impl GenericNetworkStream {
    pub(crate) fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr(),
            Self::Tls(stream) => TcpStream::peer_addr(&stream.get_ref().0),
            Self::Quic(_, _, _, _, remote_addr) => Ok(*remote_addr)
        }
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.local_addr(),
            Self::Tls(stream) => TcpStream::local_addr(&stream.get_ref().0),
            Self::Quic(_, _, endpoint, _, _) => endpoint.local_addr()
        }
    }

    #[allow(dead_code)]
    pub(crate) fn quic_endpoint(&self) -> Option<Endpoint> {
        match self {
            Self::Quic(_, _, endpoint, _, _) => Some(endpoint.clone()),
            _ => None
        }
    }

    pub fn take_quic_connection(&mut self) -> Option<NewConnection> {
        match self {
            Self::Quic(_,_,_, conn, ..) => conn.take(),
            _ => None
        }
    }
}

impl AsyncRead for GenericNetworkStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Quic(_, recv, ..) => Pin::new(recv).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for GenericNetworkStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Quic(sink, ..) => Pin::new(sink).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Quic(sink, ..) => Pin::new(sink).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Quic(sink, ..) => Pin::new(sink).poll_shutdown(cx)
        }
    }
}


pub struct GenericNetworkListener {
    future: Pin<Box<dyn StreamOutputImpl>>,
    recv: tokio::sync::mpsc::Receiver<std::io::Result<(GenericNetworkStream, SocketAddr)>>,
    local_addr: SocketAddr,
    #[allow(dead_code)]
    quic_endpoint: Option<Endpoint>,
    #[allow(dead_code)]
    redirect_to_quic: Option<(TlsDomain, bool)>,
    tls_domain: TlsDomain
}

impl GenericNetworkListener {
    pub fn from_quic_node(quic_node: QuicNode, is_self_signed: bool) -> std::io::Result<Self> {
        let endpoint = quic_node.endpoint.clone();
        let local_addr = quic_node.endpoint.local_addr()?;
        let tls_domain = quic_node.tls_domain_opt.clone();
        let mut listener = QuicListener::new(quic_node, is_self_signed);
        let (send, recv) = tokio::sync::mpsc::channel(1024);

        let future = async move {
            while let Some(stream) = listener.next().await {
                let res = stream.map(|(conn, tx, rx, peer_addr, endpoint)| {
                    (GenericNetworkStream::Quic(tx,rx, endpoint, Some(conn), peer_addr), peer_addr)
                });

                log::info!("RECV raw QUIC stream from {:?}", res);
                send.send(res).await.map_err(|err| generic_error(err.to_string()))?;
            }

            Err(generic_error("QUIC listener died"))
        };

        Ok(Self {
            future: Box::pin(future),
            recv,
            local_addr,
            quic_endpoint: Some(endpoint),
            redirect_to_quic: None,
            tls_domain,
        })
    }

    pub fn new_tcp(listener: TcpListener, redirect_to_quic: Option<(TlsDomain, bool)>) -> std::io::Result<Self> {
        let (send, recv) = tokio::sync::mpsc::channel(1024);
        let local_addr = listener.local_addr()?;
        let tls_domain = redirect_to_quic.as_ref().map(|r| r.0.clone()).flatten();

        let future = async move {
            let ref redirect_to_quic = redirect_to_quic;
            loop {
                let (stream, addr) = listener.accept().await?;
                log::info!("Received raw TCP stream from {:?}: {:?}", addr, stream);

                // ensures that any errors do not terminate the listener as a whole
                async fn handle_stream_non_terminating(stream: TcpStream, addr: SocketAddr, redirect_to_quic: &Option<(TlsDomain, bool)>) -> std::io::Result<(GenericNetworkStream, SocketAddr)> {
                    let first_packet = if let Some((domain, is_self_signed)) = redirect_to_quic {
                        stream.set_nodelay(true)?;
                        FirstPacket::Quic { domain: domain.clone(), external_addr: addr, is_self_signed: *is_self_signed }
                    } else {
                        FirstPacket::Tcp { external_addr: addr }
                    };

                    let conn = super::write_one_packet(stream, first_packet.serialize_to_vector().map_err(|err| generic_error(err.to_string()))?).await.map_err(|err| generic_error(err.to_string()))?;
                    Ok((GenericNetworkStream::Tcp(conn), addr))
                }

                send.send(handle_stream_non_terminating(stream, addr, redirect_to_quic).await).await.map_err(|err| generic_error(err.to_string()))?;
            }
        };

        Ok(Self {
            future: Box::pin(future),
            recv,
            local_addr,
            quic_endpoint: None,
            redirect_to_quic: None,
            tls_domain,
        })
    }

    pub fn new_tls(mut listener: TlsListener) -> std::io::Result<Self> {
        let (send, recv) = tokio::sync::mpsc::channel(1024);
        let local_addr = listener.local_addr;
        let tls_domain = listener.tls_domain.clone();

        let future = async move {
            loop {
                let (stream, addr) = listener.next().await.ok_or_else(|| generic_error("TLS listener died"))??;
                log::info!("Received raw TLS stream from {:?}: {:?}", addr, stream);
                send.send(Ok((GenericNetworkStream::Tls(stream.into()), addr))).await.map_err(|err| generic_error(err.to_string()))?;
            }
        };

        Ok(Self {
            future: Box::pin(future),
            recv,
            local_addr,
            quic_endpoint: None,
            redirect_to_quic: None,
            tls_domain,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    #[allow(dead_code)]
    pub fn tls_domain(&self) -> TlsDomain {
        self.tls_domain.clone()
    }

    /// For P2P connections, this should exist
    #[allow(dead_code)]
    pub fn quic_endpoint(&self) -> Option<Endpoint> {
        self.quic_endpoint.clone()
    }
}

impl Stream for GenericNetworkListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            future,
            recv,
            ..
        } = &mut *self;

        // if this future ends, it's over
        match future.as_mut().poll(cx) {
            Poll::Pending => {},
            Poll::Ready(res) => {
                // assert err
                log::warn!("ERR: {:?}", res);
                return Poll::Ready(Some(Err(res.unwrap_err())))
            }
        }

        Pin::new(recv).poll_recv(cx)
    }
}


pub struct TlsListener {
    future: Pin<Box<dyn StreamOutputImpl>>,
    recv: tokio::sync::mpsc::Receiver<std::io::Result<(TlsStream<TcpStream>, SocketAddr)>>,
    local_addr: SocketAddr,
    tls_domain: TlsDomain
}

impl TlsListener {
    pub fn new(inner: TcpListener, tls_acceptor: TlsAcceptor, domain: TlsDomain, is_self_signed: bool) -> std::io::Result<Self> {
        let (send, recv) = tokio::sync::mpsc::channel(1024);
        let local_addr = inner.local_addr()?;
        let tls_domain = domain.clone();

        let future = async move {
            let ref tls_acceptor = tls_acceptor;
            let ref domain = domain;
            let ref send = send;

            let acceptor_stream = async_stream::stream! {
                    loop {
                        yield inner.accept().await
                    }
            };

            acceptor_stream.try_for_each_concurrent(None, |(stream, addr)| async move {
                log::info!("TLs-listener RECV Raw TCP stream from {:?} : {:?}",addr, stream);
                let domain = domain.clone();

                async fn handle_stream_non_terminating(stream: TcpStream, addr: SocketAddr, domain: TlsDomain, is_self_signed: bool, tls_acceptor: &TlsAcceptor) -> std::io::Result<(TlsStream<TcpStream>, SocketAddr)> {
                    let serialized_first_packet = FirstPacket::Tls { domain, external_addr: addr, is_self_signed }.serialize_to_vector().map_err(|err| generic_error(err.to_string()))?;
                    let stream = super::write_one_packet(stream, serialized_first_packet).await.map_err(|err| generic_error(err.into_string()))?;
                    // Upgrade TCP stream to TLS stream
                    tls_acceptor.accept(stream).await.map(|r| (r, addr))
                }

                send.send(handle_stream_non_terminating(stream, addr, domain, is_self_signed, tls_acceptor).await).await.map_err(|err| generic_error(err.to_string()))
            }).await
        };

        Ok(Self {
            future: Box::pin(future),
            recv,
            local_addr,
            tls_domain
        })
    }

    /// Given a path and password, returns the asymmetric crypto identity
    /// Also stores the QUIC keys for use in case of P2P
    #[allow(dead_code)]
    pub fn load_tls_pkcs<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T) -> Result<TLSQUICInterop, NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        hyxe_wire::tls::create_server_config(&bytes, password.as_ref()).map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

impl Stream for TlsListener {
    type Item = std::io::Result<(TlsStream<TcpStream>, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            future,
            recv,
            ..
        } = &mut *self;

        // if this future ends, it's over
        match future.as_mut().poll(cx) {
            Poll::Pending => {},
            Poll::Ready(res) => {
                // assert err
                log::warn!("ERR: {:?}", res);
                return Poll::Ready(Some(Err(res.unwrap_err())))
            }
        }

        Pin::new(recv).poll_recv(cx)
    }
}

pub struct QuicListener {
    future: Pin<Box<dyn StreamOutputImpl>>,
    recv: tokio::sync::mpsc::Receiver<std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>>,
    #[allow(dead_code)]
    is_self_signed: bool
}

impl QuicListener {
    pub fn new(mut server: QuicNode, is_self_signed: bool) -> Self {
        let (send, recv) = tokio::sync::mpsc::channel(1024);
        let endpoint = server.endpoint.clone();

        let future = async move {
            loop {
                let ref mut server = server;

                let acceptor_stream = async_stream::stream! {
                    loop {
                        let res = server.next_connection().await.map_err(|err| generic_error(err.to_string()));
                        match res {
                            Err(res) => {
                                if res.to_string().contains(hyxe_wire::quic::QUIC_LISTENER_DIED) {
                                    // terminate by yielding error
                                    yield Err(res)
                                } else {
                                    log::warn!("QUIC accept err: {:?}", res);
                                }
                            }

                            res => yield res
                        }
                    }
                };

                let ref endpoint = endpoint;
                let ref send = send;

                acceptor_stream.try_for_each_concurrent(None, |(conn, tx, rx)| async move {
                    let addr = conn.connection.remote_address();
                    log::info!("RECV {:?} from {:?}", &conn, addr);
                    send.send(Ok((conn, tx, rx, addr, endpoint.clone()))).await.map_err(|err| generic_error(err.to_string()))
                }).await?;
            }
        };

        Self {
            future: Box::pin(future),
            recv,
            is_self_signed
        }
    }
}

trait StreamOutputImpl: Future<Output=std::io::Result<()>> + SyncContextRequirements {}
impl<T: Future<Output=std::io::Result<()>> + SyncContextRequirements> StreamOutputImpl for T {}

impl Stream for QuicListener {
    type Item = std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            future,
            recv,
            ..
        } = &mut *self;

        // if this future ends, it's over
        match future.as_mut().poll(cx) {
            Poll::Pending => {},
            Poll::Ready(res) => {
                // assert err
                log::warn!("ERR: {:?}", res);
                return Poll::Ready(Some(Err(res.unwrap_err())))
            }
        }

        Pin::new(recv).poll_recv(cx)
    }
}


#[derive(Serialize, Deserialize)]
pub enum FirstPacket {
    Tcp { external_addr: SocketAddr },
    Tls { domain: TlsDomain, external_addr: SocketAddr, is_self_signed: bool },
    Quic { domain: TlsDomain, external_addr: SocketAddr, is_self_signed: bool }
}

pub struct DualListener {
    future: Pin<Box<dyn StreamOutputImpl>>,
    recv: tokio::sync::mpsc::Receiver<std::io::Result<(GenericNetworkStream, SocketAddr)>>
}

impl DualListener {
    pub fn new(mut tcp_or_tls_listener: GenericNetworkListener, quic_listener: Option<GenericNetworkListener>) -> Self {
        let (tx, recv) = tokio::sync::mpsc::channel(1024);
        let tx2 = tx.clone();
        let redirects_to_quic = quic_listener.is_some();

        let future = async move {
            let tcp_or_tls_listener_future = async move {
                loop {
                    match tcp_or_tls_listener.next().await {
                        Some(res) => {
                            let res = res;
                            // only return value IF the dual listener only returns quic streams
                            if !redirects_to_quic {
                                tx.send(res).await.map_err(|err| generic_error(err.to_string()))?
                            }
                        },
                        None => return Err::<(), _>(generic_error("Tcp_or_tls stream died"))
                    }
                }
            };

            let quic_listener_future = async move {
                if let Some(mut quic_listener) = quic_listener {
                    loop {
                        match quic_listener.next().await {
                            Some(res) => tx2.send(res).await.map_err(|err| generic_error(err.to_string()))?,
                            None => return Err::<(), _>(generic_error("Tcp_or_tls stream died"))
                        }
                    }
                } else {
                    Ok(())
                }
            };

            tokio::try_join!(tcp_or_tls_listener_future, quic_listener_future).map(|_| ())
        };

        Self {
            future: Box::pin(future),
            recv
        }
    }
}

impl Stream for DualListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            future,
            recv,
            ..
        } = &mut *self;

        // if this future ends, it's over
        match future.as_mut().poll(cx) {
            Poll::Pending => {},
            Poll::Ready(res) => {
                // assert err
                log::warn!("ERR: {:?}", res);
                return Poll::Ready(Some(Err(res.unwrap_err())))
            }
        }

        Pin::new(recv).poll_recv(cx)
    }
}