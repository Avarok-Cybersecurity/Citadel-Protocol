use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_io::{ProtocolIO, ServerMode, UnreliableDatagram};

/// ProtocolIO for WebAssembly targets.
///
/// Initial implementation stubs transport operations.
/// Future phases will add WebSocket (C2S) and WebRTC (P2P) connections.
#[derive(Clone)]
pub struct WasmIO;

/// WASM stream — placeholder for future WebSocket/WebRTC stream.
pub struct WasmStream;

impl Unpin for WasmStream {}

impl AsyncRead for WasmStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASM stream not yet implemented",
        )))
    }
}

impl AsyncWrite for WasmStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASM stream not yet implemented",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// WASM listener — client-only, never yields connections.
pub struct WasmListener;

impl futures::Stream for WasmListener {
    type Item = io::Result<(WasmStream, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Unpin for WasmListener {}

/// WASM UDP socket — errors on all operations (browser has no raw UDP).
pub struct WasmUnreliableSocket;

impl UnreliableDatagram for WasmUnreliableSocket {
    type Addr = SocketAddr;

    async fn send_to(&self, _buf: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw UDP not available on WASM",
        ))
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw UDP not available on WASM",
        ))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw UDP not available on WASM",
        ))
    }
}

/// Config types for WASM.
#[derive(Clone, Debug)]
pub struct WasmOrderedReliableConfig;
#[derive(Clone, Debug)]
pub struct WasmSecureConfig;
#[derive(Clone, Debug)]
pub struct WasmP2PConfig;
#[derive(Clone, Debug)]
pub struct WasmClientConfig;

impl ProtocolIO for WasmIO {
    type Addr = SocketAddr;
    type Stream = WasmStream;
    type Listener = WasmListener;
    type UnreliableSocket = WasmUnreliableSocket;
    type OrderedReliableConfig = WasmOrderedReliableConfig;
    type SecureConfig = WasmSecureConfig;
    type P2PConfig = WasmP2PConfig;
    type ClientConfig = WasmClientConfig;
    type Rng = citadel_io::wasm::rng::WasmRng;

    async fn bind(
        _config: ServerMode<Self>,
        _addr: SocketAddr,
    ) -> io::Result<(Self::Listener, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server bind not available on WASM",
        ))
    }

    async fn connect(_config: &Self::ClientConfig, _addr: SocketAddr) -> io::Result<Self::Stream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASM connect not yet implemented",
        ))
    }

    async fn bind_unreliable(_addr: SocketAddr) -> io::Result<Self::UnreliableSocket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw UDP not available on WASM",
        ))
    }

    fn rng() -> Self::Rng {
        citadel_io::wasm::rng::WasmRng
    }

    async fn default_client_config() -> io::Result<Self::ClientConfig> {
        Ok(WasmClientConfig)
    }

    fn server_identity(_config: &ServerMode<Self>) -> Option<String> {
        None
    }

    fn local_addr(_stream: &Self::Stream) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASM stream has no local addr",
        ))
    }

    async fn default_server_config() -> io::Result<ServerMode<Self>> {
        // WASM is client-only. Peer nodes don't use the server config for binding,
        // so we return a valid placeholder to allow Peer node initialization.
        Ok(ServerMode::OrderedReliable(WasmOrderedReliableConfig))
    }

    fn from_socket_addr(addr: SocketAddr) -> SocketAddr {
        addr
    }

    fn to_socket_addr(addr: &SocketAddr) -> SocketAddr {
        *addr
    }

    fn addr_port(addr: &SocketAddr) -> u16 {
        addr.port()
    }

    fn peer_addr(_stream: &Self::Stream) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASM stream has no peer addr",
        ))
    }

    fn take_p2p_connection(_stream: &mut Self::Stream) -> Option<Box<dyn std::any::Any + Send>> {
        // WasmStream doesn't hold a connection yet.
        // Future phases (WebRTC) will have WasmStream hold a Connection,
        // and this will return Some(Box::new(connection)).
        None
    }

    fn client_config_to_any(config: &Self::ClientConfig) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(config.clone()))
    }
}
