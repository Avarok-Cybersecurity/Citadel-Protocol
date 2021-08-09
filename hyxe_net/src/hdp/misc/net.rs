use tokio_util::codec::LengthDelimitedCodec;
use crate::hdp::misc::clean_shutdown::{clean_framed_shutdown, CleanShutdownSink, CleanShutdownStream};
use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncRead, ReadBuf, AsyncWriteExt};
use crate::macros::{ContextRequirements, SyncContextRequirements};
use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio_stream::Stream;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::ops::DerefMut;
use std::io::{Error, Write};
use hyxe_nat::exports::tokio_rustls::{server::TlsStream, TlsAcceptor};
use futures::{Future, StreamExt};
use std::sync::Arc;
//use tokio_native_tls::native_tls::{Identity, Certificate};
use std::path::Path;
use crate::error::NetworkError;
use crate::hdp::hdp_server::TlsDomain;
use serde::{Serialize, Deserialize};
use hyxe_fs::io::SyncIO;
use hyxe_nat::exports::{SendStream, RecvStream, Endpoint, Incoming, Connecting, NewConnection};
use hyxe_nat::quic::QuicNode;
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
    Tcp(TcpListener, Option<(TlsDomain, bool)>),
    Tls(TlsListener),
    Quic(QuicListener)
}

impl GenericNetworkListener {
    pub fn from_quic_node(quic: QuicNode, is_self_signed: bool) -> Self {
        let endpoint = quic.endpoint;
        let incoming = quic.listener;
        let domain = quic.tls_domain_opt;

        Self::Quic(QuicListener { endpoint, incoming, domain, queue: Vec::new(), is_self_signed})
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener, ..) => listener.local_addr(),
            Self::Tls(listener) => listener.inner.local_addr(),
            Self::Quic(listener) => listener.endpoint.local_addr()
        }
    }

    pub fn tls_domain(&self) -> TlsDomain {
        match self {
            Self::Tcp(..) => None,
            Self::Tls(tls) => tls.domain.clone(),
            Self::Quic(quic) => quic.domain.clone()
        }
    }

    /// For P2P connections, this should exist
    pub fn quic_endpoint(&self) -> Option<Endpoint> {
        match self {
            Self::Tcp(..) | Self::Tls(..) => None,
            Self::Quic(quic) => Some(quic.endpoint.clone())
        }
    }
}

impl Stream for GenericNetworkListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.deref_mut() {
            Self::Tcp(ref listener, redirect_to_quic) => {
                match futures::ready!(listener.poll_accept(cx)) {
                    Ok((stream, addr)) => {
                        let mut stream = stream.into_std()?;
                        stream.set_nonblocking(false)?;
                        if let Some((domain, is_self_signed)) = redirect_to_quic {
                            let _ = stream.write(&FirstPacket::Quic { domain: domain.clone(), external_addr: addr, is_self_signed: *is_self_signed }.serialize_to_vector().unwrap())?;
                        } else {
                            let _ = stream.write(&FirstPacket::Tcp { external_addr: addr }.serialize_to_vector().unwrap())?;
                        }

                        stream.set_nonblocking(true)?;

                        Poll::Ready(Some(Ok((GenericNetworkStream::Tcp(tokio::net::TcpStream::from_std(stream)?), addr))))
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

            Self::Quic(listener) => {
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
            Ok((mut stream, peer_addr)) => {

                let tls_acceptor = tls_acceptor.clone();
                let domain = domain.clone();
                let is_self_signed = *is_self_signed;

                let future = async move {
                    //let _ = stream.write(&[TLS_CONN_TYPE] as &[u8]).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    let serialized_first_packet = FirstPacket::Tls { domain, external_addr: peer_addr, is_self_signed }.serialize_to_vector().unwrap();
                    let _ = stream.write(serialized_first_packet.as_slice()).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    // Upgrade TCP stream to TLS stream
                    tls_acceptor.accept(stream).await.map_err(|err| NetworkError::Generic(err.to_string()))
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
    endpoint: Endpoint,
    incoming: Incoming,
    domain: TlsDomain,
    queue: Vec<Pin<Box<dyn QuicOutputImpl>>>,
    #[allow(dead_code)]
    is_self_signed: bool
}

impl QuicListener {
    fn poll_future(future: &mut Pin<Box<dyn QuicOutputImpl>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
        future.as_mut().poll(cx).map(Some)
    }
}

trait QuicOutputImpl: Future<Output=std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>> + SyncContextRequirements {}
impl<T: Future<Output=std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>> + SyncContextRequirements> QuicOutputImpl for T {}

impl Stream for QuicListener {
    type Item = std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            incoming,
            queue,
            endpoint,
            ..
        } = &mut *self;

        for (idx, future) in queue.iter_mut().enumerate() {
            match Self::poll_future(future, cx) {
                Poll::Ready(res) => {
                    let _ = queue.remove(idx);
                    return match res {
                        Some(Ok(res)) => {
                            Poll::Ready(Some(Ok(res)))
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

        match futures::ready!(Pin::new(incoming).poll_next(cx)) {
            Some(connecting) => {
                let connecting: Connecting = connecting;
                let endpoint = endpoint.clone();

                let future = async move {
                    let remote_address = connecting.remote_address();
                    let mut conn = connecting.await.map_err(|err| generic_error(format!("{:?}", err)))?;
                    // as the server, we will await for the client to open the bi stream
                    let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| generic_error("No bi-streams can be obtained"))?.map_err(|err| generic_error(format!("{:?}", err)))?;
                    // since the client writes a null packet to open the bi-stream, we just have to read the first amt
                    //let _ = stream.read(&mut []).await?;
                    Ok((conn, sink, stream, remote_address, endpoint))
                };

                let mut future = Box::pin(future) as Pin<Box<dyn QuicOutputImpl>>;
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

            None => {
                log::warn!("QUIC Listener error (stream returned None)");
                Poll::Ready(None)
            }
        }

    }
}


#[derive(Serialize, Deserialize)]
pub enum FirstPacket {
    Tcp { external_addr: SocketAddr },
    Tls { domain: TlsDomain, external_addr: SocketAddr, is_self_signed: bool },
    Quic { domain: TlsDomain, external_addr: SocketAddr, is_self_signed: bool }
}

pub struct DualListener {
    pub listener_0: GenericNetworkListener,
    pub quic: Option<GenericNetworkListener>
}

impl Stream for DualListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.listener_0).poll_next(cx) {
            Poll::Ready(res) => return Poll::Ready(res),
            Poll::Pending => {
                if let Some(quic_listener) = self.quic.as_mut() {
                    Pin::new(quic_listener).poll_next(cx)
                } else {
                    Poll::Pending
                }
            }
        }
    }
}