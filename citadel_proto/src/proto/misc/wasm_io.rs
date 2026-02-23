//! ProtocolIO implementation for WebAssembly targets.
//!
//! Uses the browser WebSocket API for C2S connections and WebRTC DataChannels
//! for P2P connections. [`WasmStream`] is an enum over both transports.
#![allow(unsafe_code)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use citadel_io::{ProtocolIO, ServerMode, UnreliableDatagram};

use super::wasm_stream::{SendFuture, WasmStream, WasmWebSocketStream};

/// ProtocolIO for WebAssembly targets.
///
/// Uses browser WebSocket for C2S connections.
/// Uses WebRTC DataChannels for P2P connections.
#[derive(Clone)]
pub struct WasmIO;

// ── Listener ────────────────────────────────────────────────────────

/// WASM listener — yields completed WebRTC DataChannel connections.
pub enum WasmListener {
    /// Client-only stub; never yields connections.
    Stub,
    /// WebRTC-backed listener yielding DataChannel connections via signaling.
    Rtc(WasmRtcListener),
}

impl futures::Stream for WasmListener {
    type Item = io::Result<(WasmStream, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::Stub => Poll::Pending,
            Self::Rtc(rtc) => Pin::new(rtc).poll_next(cx),
        }
    }
}

impl Unpin for WasmListener {}

/// Receives completed WebRTC DataChannel connections from the signaling layer.
pub struct WasmRtcListener {
    pub rx: citadel_io::tokio::sync::mpsc::UnboundedReceiver<io::Result<(WasmStream, SocketAddr)>>,
}

impl futures::Stream for WasmRtcListener {
    type Item = io::Result<(WasmStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Unpin for WasmRtcListener {}

// ── Unreliable socket ───────────────────────────────────────────────

/// WASM UDP socket — errors on all operations (browsers have no raw UDP).
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

// ── Configuration types ─────────────────────────────────────────────

/// Client configuration for WASM WebSocket transport.
#[derive(Clone)]
pub struct WasmClientConfig {
    /// Use `wss://` (true) or `ws://` (false).
    pub use_tls: bool,
    /// Pre-established stream for serverless client mode.
    /// First `connect()` call takes it; subsequent calls use normal WebSocket.
    pub pre_built_stream: Option<std::sync::Arc<std::sync::Mutex<Option<WasmStream>>>>,
}

#[derive(Clone, Debug)]
pub struct WasmOrderedReliableConfig;

#[derive(Clone, Debug)]
pub struct WasmSecureConfig;

/// ICE server configuration for WebRTC connections (STUN and/or TURN).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IceServerConfig {
    /// URLs, e.g. `["stun:stun.l.google.com:19302"]` or `["turn:turn.example.com:3478"]`
    pub urls: Vec<String>,
    /// Username (required for TURN, absent for STUN).
    pub username: Option<String>,
    /// Credential (required for TURN, absent for STUN).
    pub credential: Option<String>,
}

/// P2P configuration for WASM — carries ICE servers for WebRTC.
#[derive(Clone, Debug)]
pub struct WasmP2PConfig {
    pub ice_servers: Vec<IceServerConfig>,
}

// ── ProtocolIO impl ─────────────────────────────────────────────────

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
        config: ServerMode<Self>,
        _addr: SocketAddr,
    ) -> io::Result<(Self::Listener, SocketAddr)> {
        match config {
            ServerMode::P2P(_p2p_config) => {
                let (_, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
                let listener = WasmListener::Rtc(WasmRtcListener { rx });
                // Sentinel addr — WASM has no real bind address.
                Ok((listener, SocketAddr::from(([0, 0, 0, 0], 0))))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WASM server bind requires P2P mode (WebRTC)",
            )),
        }
    }

    fn connect(
        config: &Self::ClientConfig,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        let pre_built = config
            .pre_built_stream
            .as_ref()
            .and_then(|m| m.lock().unwrap().take());
        let use_tls = config.use_tls;
        SendFuture(async move {
            if let Some(stream) = pre_built {
                return Ok(stream);
            }
            let scheme = if use_tls { "wss" } else { "ws" };
            let url = format!("{scheme}://{addr}");
            WasmWebSocketStream::connect(&url)
                .await
                .map(WasmStream::WebSocket)
        })
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
        Ok(WasmClientConfig {
            use_tls: false,
            pre_built_stream: None,
        })
    }

    fn server_identity(_config: &ServerMode<Self>) -> Option<String> {
        None
    }

    fn local_addr(_stream: &Self::Stream) -> io::Result<SocketAddr> {
        // Browser streams don't expose local addr; return a sentinel.
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    async fn default_server_config() -> io::Result<ServerMode<Self>> {
        Ok(ServerMode::P2P(WasmP2PConfig {
            ice_servers: Vec::new(),
        }))
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
        None
    }

    fn client_config_to_any(config: &Self::ClientConfig) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(config.clone()))
    }
}
