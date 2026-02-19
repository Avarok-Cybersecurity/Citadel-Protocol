use crate::tokio::io::{AsyncRead, AsyncWrite};
use crate::tokio_stream::StreamExt;
use bytes::Bytes;
use futures::SinkExt;
use std::fmt::{self, Debug};
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

    /// Config for ordered reliable transport without transport-level encryption
    /// (e.g. TCP for native, ws:// WebSocket for WASM).
    type OrderedReliableConfig: Clone + Send + Sync + 'static;

    /// Config for ordered reliable transport WITH transport-level encryption
    /// (e.g. TLS for native, wss:// WebSocket for WASM).
    type SecureConfig: Clone + Send + Sync + 'static;

    /// Config for P2P-capable transport with multiplexed streams
    /// (e.g. QUIC for native, WebRTC for WASM).
    type P2PConfig: Clone + Send + Sync + 'static;

    /// Client-side configuration (TLS client config, WebSocket options, etc.).
    type ClientConfig: Clone + Send + Sync + 'static;

    /// Random number generator type.
    type Rng: rand::Rng + 'static;

    /// Bind a server listener to the given address.
    fn bind(
        config: ServerMode<Self>,
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
    /// without a domain (plain ordered reliable, WASM, etc.).
    fn server_identity(config: &ServerMode<Self>) -> Option<String>;

    /// Retrieve the local address of an established stream.
    ///
    /// Returns an error if the stream doesn't support address retrieval
    /// (e.g. WASM WebSocket streams).
    fn local_addr(stream: &Self::Stream) -> io::Result<Self::Addr>;

    /// Create a default server configuration for this transport.
    ///
    /// For NativeIO, this creates a self-signed TLS configuration.
    /// For WasmIO, this would create default WebSocket server options.
    fn default_server_config() -> impl Future<Output = io::Result<ServerMode<Self>>> + Send;

    /// Log any warnings about the server configuration.
    ///
    /// Default is a no-op. Override to warn about insecure configurations
    /// (e.g. NativeIO warns about raw TCP without TLS).
    fn config_warnings(_config: &ServerMode<Self>) {}

    /// Convert a standard socket address to this protocol's address type.
    fn from_socket_addr(addr: std::net::SocketAddr) -> Self::Addr;

    /// Convert this protocol's address to a standard socket address.
    fn to_socket_addr(addr: &Self::Addr) -> std::net::SocketAddr;

    /// Extract the port number from an address.
    fn addr_port(addr: &Self::Addr) -> u16;

    /// Get the peer address of an established stream.
    fn peer_addr(stream: &Self::Stream) -> io::Result<Self::Addr>;

    /// Extract an opaque P2P connection handle from a stream (if present).
    ///
    /// Returns `None` for non-P2P streams or transports without QUIC.
    /// The returned value can be downcast to the concrete connection type
    /// (e.g. `quinn::Connection` for NativeIO).
    fn take_p2p_connection(_stream: &mut Self::Stream) -> Option<Box<dyn std::any::Any + Send>> {
        None
    }

    /// Extract an opaque handle from the client config for P2P operations.
    ///
    /// Returns `None` for transports that don't support native P2P
    /// (e.g. WASM). For NativeIO, returns `Arc<rustls::ClientConfig>`.
    fn client_config_to_any(_config: &Self::ClientConfig) -> Option<Box<dyn std::any::Any + Send>> {
        None
    }
}

/// Capability-based server configuration.
///
/// Each variant describes a transport *capability* rather than a specific
/// protocol. The concrete transport is determined by the [`ProtocolIO`]
/// implementation (e.g. `NativeIO` maps `OrderedReliableSecure` to TLS,
/// while a future `WasmIO` would map it to WSS).
pub enum ServerMode<T: ProtocolIO> {
    /// Ordered reliable stream without transport-level encryption
    /// (TCP in native, ws:// WebSocket in WASM).
    OrderedReliable(T::OrderedReliableConfig),

    /// Ordered reliable stream with transport-level encryption
    /// (TLS in native, wss:// WebSocket in WASM).
    OrderedReliableSecure(T::SecureConfig),

    /// P2P-capable transport with multiplexed streams
    /// (QUIC in native, WebRTC in WASM).
    P2P(T::P2PConfig),
}

impl<T: ProtocolIO> Clone for ServerMode<T> {
    fn clone(&self) -> Self {
        match self {
            Self::OrderedReliable(c) => Self::OrderedReliable(c.clone()),
            Self::OrderedReliableSecure(c) => Self::OrderedReliableSecure(c.clone()),
            Self::P2P(c) => Self::P2P(c.clone()),
        }
    }
}

impl<T: ProtocolIO> Debug for ServerMode<T>
where
    T::OrderedReliableConfig: Debug,
    T::SecureConfig: Debug,
    T::P2PConfig: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrderedReliable(c) => f.debug_tuple("OrderedReliable").field(c).finish(),
            Self::OrderedReliableSecure(c) => {
                f.debug_tuple("OrderedReliableSecure").field(c).finish()
            }
            Self::P2P(c) => f.debug_tuple("P2P").field(c).finish(),
        }
    }
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

/// The two listener halves produced by [`ProtocolUpgrade::bind_upgrade_pair`].
pub struct UpgradeListenerPair<T: ProtocolIO> {
    /// Listener that accepts signaling connections (e.g. TCP for redirect).
    pub signal_listener: T::Listener,
    /// Listener that accepts the real upgraded connections (e.g. QUIC).
    pub target_listener: T::Listener,
    /// The address both listeners are bound to.
    pub bound_addr: T::Addr,
}

/// Describes a protocol redirect/upgrade: signal on one transport, accept on another.
///
/// The **default methods** encode the orchestration process:
/// - Server: bind signal listener → accept → send redirect → accept on target
/// - Client: connect → read signal → upgrade to target
///
/// **Concrete implementations** provide only the protocol-specific bits:
/// signal construction, serialization, listener creation, and connection upgrade.
///
/// # Example: TCP-to-QUIC
///
/// The native `TcpToQuicUpgrade` sends a redirect signal over TCP telling the
/// client to reconnect via QUIC on the same address. The server runs both a
/// TCP listener (for signaling) and a QUIC listener (for data), merged into
/// a single composite listener.
pub trait ProtocolUpgrade<T: ProtocolIO>: Send + Sync + 'static {
    /// Redirect signal sent from server to client over the signaling channel.
    type Signal: Clone + Send + Sync + 'static;

    // ── Concrete methods (protocol-specific) ──────────────────────

    /// Build the redirect signal for a connecting client.
    fn build_signal(target_config: &ServerMode<T>, client_addr: T::Addr) -> Self::Signal;

    /// Serialize the signal for wire transmission.
    fn serialize_signal(signal: &Self::Signal) -> io::Result<Bytes>;

    /// Deserialize signal received from server.
    fn deserialize_signal(bytes: &[u8]) -> io::Result<Self::Signal>;

    /// Create both the signaling listener and the target listener.
    ///
    /// The signaling listener accepts initial connections and sends the
    /// redirect signal. The target listener accepts the upgraded connections.
    fn bind_upgrade_pair(
        target_config: ServerMode<T>,
        addr: T::Addr,
    ) -> impl Future<Output = io::Result<UpgradeListenerPair<T>>> + Send;

    /// Client-side: given the redirect signal, connect to the target transport.
    fn connect_target(
        signal: Self::Signal,
        local_addr: T::Addr,
        remote_addr: T::Addr,
        client_config: &T::ClientConfig,
    ) -> impl Future<Output = io::Result<T::Stream>> + Send;

    // ── Default methods (orchestration process) ───────────────────

    /// Server: bind a composite listener that redirects on one transport
    /// and accepts real connections on another.
    ///
    /// 1. Calls [`bind_upgrade_pair`](Self::bind_upgrade_pair) to create both listeners
    /// 2. Spawns the signal listener to handle redirects (accept → write signal → drop)
    /// 3. Returns only the target listener (yields upgraded connections)
    fn bind_with_upgrade(
        target_config: ServerMode<T>,
        addr: T::Addr,
    ) -> impl Future<Output = io::Result<(T::Listener, T::Addr)>> + Send {
        async move {
            let pair = Self::bind_upgrade_pair(target_config, addr).await?;
            Ok((
                Self::merge_upgrade_listeners(pair.signal_listener, pair.target_listener),
                pair.bound_addr,
            ))
        }
    }

    /// Client: connect to the signaling transport, read the redirect signal,
    /// then connect to the target transport.
    fn connect_with_upgrade(
        remote_addr: T::Addr,
        client_config: &T::ClientConfig,
    ) -> impl Future<Output = io::Result<T::Stream>> + Send {
        async move {
            // 1. Connect to signaling transport
            let stream = T::connect(client_config, remote_addr.clone()).await?;
            let local_addr = T::local_addr(&stream)?;
            // 2. Read the redirect signal
            let signal = Self::read_signal_from_stream(stream).await?;
            // 3. Connect to target transport
            Self::connect_target(signal, local_addr, remote_addr, client_config).await
        }
    }

    /// Merge a signaling listener and target listener into a composite listener.
    ///
    /// The signal listener runs in the background: it accepts connections,
    /// but its streams are consumed by the signaling process (write redirect,
    /// then drop). Only the target listener's connections are yielded.
    ///
    /// This generalizes the `DualListener` pattern.
    fn merge_upgrade_listeners(
        signal_listener: T::Listener,
        target_listener: T::Listener,
    ) -> T::Listener;

    /// Read a redirect signal from a connected signaling stream using
    /// length-delimited framing.
    fn read_signal_from_stream(
        stream: T::Stream,
    ) -> impl Future<Output = io::Result<Self::Signal>> + Send {
        async move {
            let mut framed =
                crate::tokio_util::codec::LengthDelimitedCodec::builder().new_read(stream);
            let packet = framed
                .next()
                .await
                .ok_or_else(|| io::Error::other("signaling stream closed before signal"))??;
            Self::deserialize_signal(&packet)
        }
    }

    /// Write a redirect signal to a signaling stream using length-delimited
    /// framing.
    fn write_signal_to_stream(
        stream: T::Stream,
        signal: &Self::Signal,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let bytes = Self::serialize_signal(signal)?;
            let mut framed =
                crate::tokio_util::codec::LengthDelimitedCodec::builder().new_write(stream);
            framed
                .send(bytes)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            framed
                .flush()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(())
        }
    }
}
