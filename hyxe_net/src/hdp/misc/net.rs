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
use hyxe_nat::exports::tokio_rustls::{server::TlsStream, TlsAcceptor};
use futures::{Future, TryStreamExt};
use std::sync::Arc;
//use tokio_native_tls::native_tls::{Identity, Certificate};
use std::path::Path;
use crate::error::NetworkError;
use crate::hdp::hdp_node::TlsDomain;
use serde::{Serialize, Deserialize};
use hyxe_fs::io::SyncIO;
use hyxe_nat::exports::{SendStream, RecvStream, Endpoint, NewConnection};
use hyxe_nat::quic::{QuicNode, QuicEndpointListener};
use crate::hdp::peer::p2p_conn_handler::generic_error;
use std::fmt::Debug;
use hyxe_user::re_imports::__private::Formatter;
use hyxe_nat::tls::TLSQUICInterop;

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
    Tls(hyxe_nat::exports::tokio_rustls::TlsStream<TcpStream>),
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

#[allow(variant_size_differences)]
pub enum GenericNetworkListener {
    Tcp(TcpListener, Option<(TlsDomain, bool)>, Vec<Pin<Box<dyn TcpOutputImpl>>>),
    Tls(TlsListener),
    Quic(QuicListener, Endpoint, TlsDomain)
}

impl GenericNetworkListener {
    pub fn from_quic_node(quic_node: QuicNode, is_self_signed: bool) -> Self {
        let endpoint = quic_node.endpoint.clone();
        let tls_domain = quic_node.tls_domain_opt.clone();
        Self::Quic(QuicListener::new(quic_node, is_self_signed), endpoint, tls_domain)
    }

    pub fn new_tcp(listener: TcpListener, redirect_to_quic: Option<(TlsDomain, bool)>) -> Self {
        Self::Tcp(listener, redirect_to_quic, vec![])
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener, ..) => listener.local_addr(),
            Self::Tls(listener) => listener.inner.local_addr(),
            Self::Quic(_listener, endpoint, ..) => endpoint.local_addr()
        }
    }

    #[allow(dead_code)]
    pub fn tls_domain(&self) -> TlsDomain {
        match self {
            Self::Tcp(..) => None,
            Self::Tls(tls) => tls.domain.clone(),
            Self::Quic(_, _, tls_domain) => tls_domain.clone()
        }
    }

    /// For P2P connections, this should exist
    pub fn quic_endpoint(&self) -> Option<Endpoint> {
        match self {
            Self::Tcp(..) | Self::Tls(..) => None,
            Self::Quic(_, endpoint, ..) => Some(endpoint.clone())
        }
    }

    fn poll_future(future: &mut Pin<Box<dyn TcpOutputImpl>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
        future.as_mut().poll(cx).map(|r| Some(r.map(|stream| {
            let peer_addr = stream.peer_addr().unwrap();
            let stream = GenericNetworkStream::Tcp(stream);
            (stream, peer_addr)
        }).map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))))
    }
}

pub trait TcpOutputImpl: Future<Output=Result<TcpStream, NetworkError>> + SyncContextRequirements {}
impl<T: Future<Output=Result<TcpStream, NetworkError>> + SyncContextRequirements> TcpOutputImpl for T {}

impl Stream for GenericNetworkListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.deref_mut() {
            Self::Tcp(ref listener, redirect_to_quic, writers_queue) => {

                for (idx, future) in writers_queue.iter_mut().enumerate() {
                    match Self::poll_future(future, cx) {
                        Poll::Ready(res) => {
                            let _ = writers_queue.remove(idx);
                            return match res {
                                Some(Ok((stream, peer_addr))) => {
                                    Poll::Ready(Some(Ok((stream, peer_addr))))
                                }

                                Some(Err(err)) => {
                                    Poll::Ready(Some(Err(err)))
                                }

                                None => {
                                    log::error!("TlsListener: Polled none");
                                    Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Polled none"))))
                                }
                            }
                        }

                        Poll::Pending => {} // don't return, just keep polling any additional futures
                    }
                }

                match futures::ready!(listener.poll_accept(cx)) {
                    Ok((stream, addr)) => {
                        log::info!("Received raw TCP stream from {:?}: {:?}", addr, stream);
                        let first_packet = if let Some((domain, is_self_signed)) = redirect_to_quic {
                            FirstPacket::Quic { domain: domain.clone(), external_addr: addr, is_self_signed: *is_self_signed }
                        } else {
                            FirstPacket::Tcp { external_addr: addr }
                        };

                        let future = async move {
                            super::write_one_packet(stream, first_packet.serialize_to_vector().map_err(|err| NetworkError::Generic(err.to_string()))?).await
                        };

                        let mut future = Box::pin(future) as Pin<Box<dyn TcpOutputImpl>>;
                        // poll the future once to register any internal wakers
                        let poll_res = Self::poll_future(&mut future, cx);

                        match poll_res {
                            Poll::Pending => {
                                writers_queue.push(future);
                                Poll::Pending
                            }

                            res => {
                                log::warn!("Will not enqueue future since already finished");
                                res
                            }
                        }
                    }

                    Err(err) => {
                        Poll::Ready(Some(Err(err)))
                    }
                }
            },

            Self::Tls(ref mut listener) => {
                // tls already sends the first packet. Nothing to do here
                Pin::new(listener).poll_next(cx).map(|r| r.map(|res: std::io::Result<(TlsStream<TcpStream>, SocketAddr)>| res.map(|(stream, peer_addr)| (GenericNetworkStream::Tls(stream.into()), peer_addr))))
            }

            Self::Quic(listener, ..) => {
                log::info!("Polling quic_listener from GenericNetworkListener");
                // QUIC listener already sends the first packet. Nothing to do here
                Pin::new(listener).poll_next(cx).map(|r| r.map(|res: std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>| res.map(|(conn, sink, stream, peer_addr, endpoint)| (GenericNetworkStream::Quic(sink, stream, endpoint, Some(conn), peer_addr), peer_addr))))
            }
        }
    }
}


pub struct TlsListener {
    inner: TcpListener,
    tls_acceptor: Arc<TlsAcceptor>,
    domain: TlsDomain,
    queue: Vec<Pin<Box<dyn TlsOutputImpl>>>,
    is_self_signed: bool
}

trait TlsOutputImpl: Future<Output=Result<TlsStream<TcpStream>, NetworkError>> + SyncContextRequirements {}
impl<T: Future<Output=Result<TlsStream<TcpStream>, NetworkError>> + SyncContextRequirements> TlsOutputImpl for T {}

impl TlsListener {
    pub fn new(inner: TcpListener, tls_acceptor: TlsAcceptor, domain: TlsDomain, is_self_signed: bool) -> std::io::Result<Self> {
        Ok(Self { inner, tls_acceptor: Arc::new(tls_acceptor), queue: Vec::new(), domain, is_self_signed })
    }

    /// Given a path and password, returns the asymmetric crypto identity
    /// Also stores the QUIC keys for use in case of P2P
    #[allow(dead_code)]
    pub fn load_tls_pkcs<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T) -> Result<TLSQUICInterop, NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        hyxe_nat::tls::create_server_config(&bytes, password.as_ref()).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_future(future: &mut Pin<Box<dyn TlsOutputImpl>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
        future.as_mut().poll(cx).map(|r| Some(r.map(|stream| {
            let peer_addr = TcpStream::peer_addr(&stream.get_ref().0).unwrap();
            (stream, peer_addr)
        }).map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))))
    }
}

impl Stream for TlsListener {
    type Item = std::io::Result<(TlsStream<TcpStream>, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            inner,
            tls_acceptor,
            queue,
            domain, is_self_signed
        } = &mut *self;

        for (idx, future) in queue.iter_mut().enumerate() {
            match Self::poll_future(future, cx) {
                Poll::Ready(res) => {
                    let _ = queue.remove(idx);
                    return match res {
                        Some(Ok((stream, peer_addr))) => {
                            Poll::Ready(Some(Ok((stream, peer_addr))))
                        }

                        Some(Err(err)) => {
                            Poll::Ready(Some(Err(err)))
                        }

                        None => {
                            log::error!("TlsListener: Polled none");
                            Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Polled none"))))
                        }
                    }
                }

                Poll::Pending => {} // don't return, just keep polling any additional futures
            }
        }

        match futures::ready!(Pin::new(inner).poll_accept(cx)) {
            Ok((stream, peer_addr)) => {
                log::info!("TLs-listener RECV Raw TCP stream: {:?}", stream);
                let tls_acceptor = tls_acceptor.clone();
                let domain = domain.clone();
                let is_self_signed = *is_self_signed;

                let future = async move {
                    //let _ = stream.write(&[TLS_CONN_TYPE] as &[u8]).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    let serialized_first_packet = FirstPacket::Tls { domain, external_addr: peer_addr, is_self_signed }.serialize_to_vector().unwrap();
                    let stream = super::write_one_packet(stream, serialized_first_packet).await?;
                    // Upgrade TCP stream to TLS stream
                    let res = tls_acceptor.accept(stream).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    Ok(res)
                };

                let mut future = Box::pin(future) as Pin<Box<dyn TlsOutputImpl>>;
                // poll the future once to register any internal wakers
                let poll_res = Self::poll_future(&mut future, cx);

                match poll_res {
                    Poll::Pending => {
                        queue.push(future);
                        Poll::Pending
                    }

                    res => {
                        log::warn!("Will not enqueue future since already finished");
                        res
                    }
                }
            }

            Err(err) => {
                log::error!("TLS Listener error: {:?}", err);
                Poll::Ready(None)
            }
        }
    }
}

pub struct QuicListener {
    future: Pin<Box<dyn StreamOutputImpl>>,
    recv: tokio::sync::mpsc::Receiver<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>,
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
                        yield server.next_connection().await.map_err(|err| generic_error(err.to_string()))
                    }
                };

                let ref endpoint = endpoint;
                let ref send = send;

                acceptor_stream.try_for_each_concurrent(None, |(conn, tx, rx)| async move {
                    let addr = conn.connection.remote_address();
                    log::info!("RECV {:?} from {:?}", &conn, addr);
                    send.send((conn, tx, rx, addr, endpoint.clone())).await.map_err(|err| generic_error(err.to_string()))
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
        log::info!("Polling quic_listener from QuicListener");
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

        Pin::new(recv).poll_recv(cx).map(|r| r.map(Ok))
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
    recv: tokio::sync::mpsc::Receiver<(GenericNetworkStream, SocketAddr)>
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
                            let res = res?;
                            // only return value IF the dual listener only returns quic values
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
                            Some(res) => tx2.send(res?).await.map_err(|err| generic_error(err.to_string()))?,
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

        Pin::new(recv).poll_recv(cx).map(|r| r.map(Ok))
    }
}