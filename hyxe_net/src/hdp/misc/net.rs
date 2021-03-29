use tokio_util::codec::LengthDelimitedCodec;
use crate::hdp::misc::clean_shutdown::{clean_framed_shutdown, CleanShutdownSink, CleanShutdownStream};
use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncRead, ReadBuf};
use crate::macros::ContextRequirements;
use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio_stream::Stream;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::ops::DerefMut;
use std::io::Error;
use tokio_native_tls::{TlsStream, TlsAcceptor};
use futures::Future;
use std::sync::Arc;
use tokio_native_tls::native_tls::{Identity, Certificate};
use std::path::Path;
use crate::error::NetworkError;

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

pub enum GenericNetworkStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>)
}

impl GenericNetworkStream {
    pub(crate) fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr(),
            Self::Tls(stream) => stream.get_ref().get_ref().get_ref().peer_addr()
        }
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.local_addr(),
            Self::Tls(stream) => stream.get_ref().get_ref().get_ref().local_addr()
        }
    }
}

impl AsyncRead for GenericNetworkStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for GenericNetworkStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.deref_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx)
        }
    }
}

pub enum GenericNetworkListener {
    Tcp(TcpListener),
    Tls(TlsListener)
}

impl GenericNetworkListener {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            Self::Tls(listener) => listener.inner.local_addr()
        }
    }
}

impl Stream for GenericNetworkListener {
    type Item = std::io::Result<(GenericNetworkStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.deref_mut() {
            Self::Tcp(ref listener) => {
                listener.poll_accept(cx).map(|r| Some(r.map(|(stream, addr)| (GenericNetworkStream::Tcp(stream), addr))))
            },

            Self::Tls(ref mut listener) => {
                Pin::new(listener).poll_next(cx).map(|r| r.map(|res: std::io::Result<(TlsStream<TcpStream>, SocketAddr)>| res.map(|(stream, peer_addr)| (GenericNetworkStream::Tls(stream), peer_addr))))
            }
        }
    }
}


pub struct TlsListener {
    inner: TcpListener,
    tls_acceptor: Arc<TlsAcceptor>,
    queue: Vec<Pin<Box<dyn Future<Output=Result<TlsStream<TcpStream>, tokio_native_tls::native_tls::Error>>>>>
}

impl TlsListener {
    pub fn new(inner: TcpListener, identity: Identity) -> std::io::Result<Self> {
        Ok(Self { inner, tls_acceptor: Arc::new(TlsAcceptor::from(tokio_native_tls::native_tls::TlsAcceptor::new(identity).map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?)), queue: Vec::new()})
    }

    pub fn new_pkcs<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T, inner: TcpListener) -> std::io::Result<Self> {
        let identity = Self::load_tls_pkcs(path, password).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.into_string()))?;
        Self::new(inner, identity)
    }

    /// Given a path and password, returns the asymmetric crypto identity
    pub fn load_tls_pkcs<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T) -> Result<Identity, NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        Identity::from_pkcs12(&bytes, password.as_ref()).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// Given a path to a pkcs and password, returns the cert
    pub fn load_tls_cert<P: AsRef<Path>>(path: P) -> Result<Certificate, NetworkError> {
        let bytes = std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        Certificate::from_pem(&bytes).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_future(future: &mut Pin<Box<dyn Future<Output=Result<TlsStream<TcpStream>, tokio_native_tls::native_tls::Error>>>>, cx: &mut Context<'_>) -> Poll<Option<<Self as Stream>::Item>> {
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
            queue
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
            Ok((stream, _peer_addr)) => {
                let tls_acceptor = tls_acceptor.clone();
                let future = async move {
                    tls_acceptor.accept(stream).await
                };

                let mut future = Box::pin(future) as Pin<Box<dyn Future<Output=Result<TlsStream<TcpStream>, tokio_native_tls::native_tls::Error>>>>;
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