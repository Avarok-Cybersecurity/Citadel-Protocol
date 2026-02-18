use crate::tokio::io::{AsyncRead, AsyncWrite};
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::io;

/// Abstracts all transport I/O for the Citadel Protocol.
///
/// `NativeIO` (TCP/TLS/QUIC/UDP) is the default implementation.
/// Future implementations (e.g. `WasmIO` using WebSocket/WebRTC) enable
/// browser support without any protocol-layer changes.
pub trait ProtocolIO: Clone + Send + Sync + 'static {
    /// Network address type (e.g. `SocketAddr` for native, URL for WASM).
    type Addr: Clone + Debug + Send + Sync + Eq + Hash + 'static;

    /// Bidirectional ordered reliable stream
    /// (TCP/TLS/QUIC in native, WebSocket in WASM).
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static;

    /// Accepts incoming ordered connections, yielding `(Stream, Addr)` pairs.
    type Listener: crate::tokio_stream::Stream<Item = io::Result<(Self::Stream, Self::Addr)>>
        + Unpin
        + Send
        + 'static;

    /// Unreliable datagram socket (UDP in native, WebRTC DataChannel in WASM).
    type UnreliableSocket: UnreliableDatagram<Addr = Self::Addr> + Send + Sync + 'static;

    /// Server-side configuration (protocol selection, TLS certs, etc.).
    type ServerConfig: Clone + Send + Sync + 'static;

    /// Client-side configuration (TLS client config, WebSocket options, etc.).
    type ClientConfig: Clone + Send + Sync + 'static;

    /// Random number generator type.
    type Rng: rand::Rng + 'static;

    /// Bind a server listener to the given address.
    fn bind(
        config: Self::ServerConfig,
        addr: Self::Addr,
    ) -> impl Future<Output = io::Result<(Self::Listener, Self::Addr)>> + Send;

    /// Connect to a remote address (client side).
    fn connect(
        config: &Self::ClientConfig,
        addr: Self::Addr,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send;

    /// Create an unreliable datagram socket bound to the given address.
    fn bind_unreliable(
        addr: Self::Addr,
    ) -> impl Future<Output = io::Result<Self::UnreliableSocket>> + Send;

    /// Obtain a random number generator instance.
    fn rng() -> Self::Rng;

    /// Create a default client configuration for this transport.
    ///
    /// For NativeIO, this loads system TLS root certificates.
    /// For WasmIO, this would create default WebSocket options.
    fn default_client_config() -> impl Future<Output = io::Result<Self::ClientConfig>> + Send;

    /// Extract a TLS/identity domain from the server configuration, if any.
    ///
    /// Used during P2P connection setup. Returns `None` for configs
    /// without a domain (plain TCP, WASM, etc.).
    fn server_identity(config: &Self::ServerConfig) -> Option<String>;

    /// Retrieve the local address of an established stream.
    ///
    /// Returns an error if the stream doesn't support address retrieval
    /// (e.g. WASM WebSocket streams).
    fn local_addr(stream: &Self::Stream) -> io::Result<Self::Addr>;

    /// Create a default server configuration for this transport.
    ///
    /// For NativeIO, this creates a self-signed TLS configuration.
    /// For WasmIO, this would create default WebSocket server options.
    fn default_server_config() -> impl Future<Output = io::Result<Self::ServerConfig>> + Send;

    /// Log any warnings about the server configuration.
    ///
    /// Default is a no-op. Override to warn about insecure configurations
    /// (e.g. NativeIO warns about raw TCP without TLS).
    fn config_warnings(_config: &Self::ServerConfig) {}
}

/// Abstraction over UDP-like unreliable datagram transport.
pub trait UnreliableDatagram: Send + Sync {
    /// Address type matching the parent `ProtocolIO::Addr`.
    type Addr;

    /// Send a datagram to the specified address.
    fn send_to(
        &self,
        buf: &[u8],
        addr: &Self::Addr,
    ) -> impl Future<Output = io::Result<usize>> + Send;

    /// Receive a datagram, returning bytes read and sender address.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, Self::Addr)>> + Send;

    /// Return the local address this socket is bound to.
    fn local_addr(&self) -> io::Result<Self::Addr>;
}
