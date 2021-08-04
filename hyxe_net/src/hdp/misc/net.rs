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
use tokio_native_tls::{TlsStream, TlsAcceptor};
use futures::Future;
use std::sync::Arc;
use tokio_native_tls::native_tls::{Identity, Certificate};
use std::path::Path;
use crate::error::NetworkError;
use crate::hdp::hdp_server::TlsDomain;
use serde::{Serialize, Deserialize};
use hyxe_fs::io::SyncIO;
use hyxe_nat::exports::{SendStream, RecvStream, Endpoint, Incoming, Connecting, NewConnection, CertificateChain, PrivateKey};
use hyxe_nat::quic::QuicNode;
use crate::hdp::peer::p2p_conn_handler::generic_error;

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

/*
/// For wrapping a safe-stream shutdown wrapper on a pre-split sink and stream
pub fn safe_split_sink_stream<S: AsyncWrite + Unpin + ContextRequirements, R: AsyncRead + Unpin + ContextRequirements>(sink: S, stream: R) -> (CleanShutdownSink<S, LengthDelimitedCodec, Bytes>, CleanShutdownStream<S, LengthDelimitedCodec, Bytes>) {
    let codec = LengthDelimitedCodec::builder()
        .length_field_offset(0) // default value
        .length_field_length(4)
        .length_adjustment(0).new_codec();

    struct Joined {
        sink: S,
        stream: R
    }

    impl AsyncWrite for Joined {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
            Pin::new(&mut self.sink).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Pin::new(&mut self.sink).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Pin::new(&mut self.sink).poll_shutdown(cx)
        }
    }

    impl AsyncRead for Joined {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    let joined = Joined { sink, stream };

    clean_framed_shutdown(tokio_util::codec::Framed::new(joined, codec))
}*/

#[allow(variant_size_differences)]
pub enum GenericNetworkStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    // local addr is first addr, remote addr is final addr
    Quic(SendStream, RecvStream, Endpoint, NewConnection, SocketAddr)
}

impl GenericNetworkStream {
    pub(crate) fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr(),
            Self::Tls(stream) => stream.get_ref().get_ref().get_ref().peer_addr(),
            Self::Quic(_, _, _, _, remote_addr) => Ok(*remote_addr)
        }
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.local_addr(),
            Self::Tls(stream) => stream.get_ref().get_ref().get_ref().local_addr(),
            Self::Quic(_, _, endpoint, _, _) => endpoint.local_addr()
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
    Tcp(TcpListener),
    Tls(TlsListener),
    Quic(QuicListener)
}

impl GenericNetworkListener {
    pub fn from_quic_node(quic: QuicNode, domain: TlsDomain) -> Self {
        let endpoint = quic.endpoint;
        let incoming = quic.listener;
        Self::Quic(QuicListener { endpoint, incoming, domain, queue: Vec::new()})
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            Self::Tls(listener) => listener.inner.local_addr(),
            Self::Quic(listener) => listener.endpoint.local_addr()
        }
    }

    pub fn tls_domain(&self) -> TlsDomain {
        match self {
            Self::Tcp(_) => None,
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
            Self::Tcp(ref listener) => {
                match futures::ready!(listener.poll_accept(cx)) {
                    Ok((stream, addr)) => {
                        let mut stream = stream.into_std()?;
                        stream.set_nonblocking(false)?;
                        let _ = stream.write(&FirstPacket::Tcp(addr).serialize_to_vector().unwrap())?;
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
                Pin::new(listener).poll_next(cx).map(|r| r.map(|res: std::io::Result<(TlsStream<TcpStream>, SocketAddr)>| res.map(|(stream, peer_addr)| (GenericNetworkStream::Tls(stream), peer_addr))))
            }

            Self::Quic(listener) => {
                // QUIC listener already sends the first packet. Nothing to do here
                Pin::new(listener).poll_next(cx).map(|r| r.map(|res: std::io::Result<(NewConnection, SendStream, RecvStream, SocketAddr, Endpoint)>| res.map(|(conn, sink, stream, peer_addr, endpoint)| (GenericNetworkStream::Quic(sink, stream, endpoint, conn, peer_addr), peer_addr))))
            }
        }
    }
}


pub struct TlsListener {
    inner: TcpListener,
    tls_acceptor: Arc<TlsAcceptor>,
    domain: TlsDomain,
    queue: Vec<Pin<Box<dyn TlsOutputImpl>>>
}

trait TlsOutputImpl: Future<Output=Result<TlsStream<TcpStream>, NetworkError>> + SyncContextRequirements {}
impl<T: Future<Output=Result<TlsStream<TcpStream>, NetworkError>> + SyncContextRequirements> TlsOutputImpl for T {}

impl TlsListener {
    pub fn new<T: Into<String>>(inner: TcpListener, identity: Identity, domain: T) -> std::io::Result<Self> {
        let domain = Some(domain.into());

        Ok(Self { inner, tls_acceptor: Arc::new(TlsAcceptor::from(tokio_native_tls::native_tls::TlsAcceptor::new(identity).map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?)), queue: Vec::new(), domain })
    }

    pub fn new_pkcs<P: AsRef<Path>, T: AsRef<str>, K: Into<String>>(path: P, password: T, domain: K, inner: TcpListener) -> std::io::Result<Self> {
        let identity = Self::load_tls_pkcs(path, password).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.into_string()))?.0;
        Self::new(inner, identity, domain.into())
    }

    /// Given a path and password, returns the asymmetric crypto identity
    /// Also stores the QUIC keys for use in case of P2P
    pub fn load_tls_pkcs<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T) -> Result<(Identity, CertificateChain, PrivateKey), NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        let (chain, priv_key) = hyxe_nat::misc::pkcs12_to_quinn_keys(&bytes, password.as_ref()).map_err(|err| NetworkError::Generic(err.to_string()))?;
        Identity::from_pkcs12(&bytes, password.as_ref()).map_err(|err| NetworkError::Generic(err.to_string()))
            .map(|ident| (ident, chain, priv_key))
    }

    /// Given a path to a pkcs and password, returns the cert
    pub fn load_tls_cert<P: AsRef<Path>>(path: P) -> Result<Certificate, NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        Certificate::from_pem(&bytes).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_future(future: &mut Pin<Box<dyn TlsOutputImpl>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
        future.as_mut().poll(cx).map(|r| Some(r.map(|stream| {
            let peer_addr = stream.get_ref().get_ref().get_ref().peer_addr().unwrap();
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
            domain
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

                let future = async move {
                    //let _ = stream.write(&[TLS_CONN_TYPE] as &[u8]).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    let serialized_first_packet = FirstPacket::Tls(domain, peer_addr).serialize_to_vector().unwrap();
                    let _ = stream.write(serialized_first_packet.as_slice()).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                    // Upgrade TCP stream to TLS stream
                    tls_acceptor.accept(stream).await.map_err(|err| NetworkError::Generic(err.to_string()))
                };

                let mut future = Box::pin(future) as Pin<Box<dyn TlsOutputImpl>>;
                // poll the future once to register any internal wakers
                let poll_res = Self::poll_future(&mut future, cx);
                queue.push(future);
                poll_res
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
    queue: Vec<Pin<Box<dyn QuicOutputImpl>>>
}

impl QuicListener {
    fn poll_future(future: &mut Pin<Box<dyn QuicOutputImpl>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
        future.as_mut().poll(cx).map(|r| Some(r))
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
            domain,
            endpoint
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
                let domain = domain.clone();

                let future = async move {
                    let remote_address = connecting.remote_address();
                    let conn = connecting.await.map_err(|err| generic_error(format!("{:?}", err)))?;
                    let (mut sink, stream) = conn.connection.open_bi().await.map_err(|err| generic_error(format!("{:?}", err)))?;
                    sink.write_all(&FirstPacket::Quic(domain, remote_address).serialize_to_vector().unwrap()).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", err)))?;
                    Ok((conn, sink, stream, remote_address, endpoint))
                };

                let mut future = Box::pin(future) as Pin<Box<dyn QuicOutputImpl>>;
                // poll the future once to register any internal wakers
                let poll_res = Self::poll_future(&mut future, cx);
                queue.push(future);
                poll_res
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
    Tcp(SocketAddr),
    Tls(TlsDomain, SocketAddr),
    Quic(TlsDomain, SocketAddr)
}

pub struct DualListener {
    pub listener_0: GenericNetworkListener,
    pub quic: Option<GenericNetworkListener>
}