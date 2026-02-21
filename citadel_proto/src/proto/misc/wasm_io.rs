//! ProtocolIO implementation for WebAssembly targets.
//!
//! Uses the browser WebSocket API (via `web-sys`) to provide real transport.
//! `WasmStream` wraps a `web_sys::WebSocket` and implements `AsyncRead + AsyncWrite`
//! by buffering incoming binary frames and sending outgoing bytes as binary messages.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_io::tokio::sync::oneshot;
use citadel_io::{ProtocolIO, ServerMode, UnreliableDatagram};

use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// ProtocolIO for WebAssembly targets.
///
/// Uses browser WebSocket for C2S connections.
/// P2P will use WebRTC in a future phase.
#[derive(Clone)]
pub struct WasmIO;

/// Shared state between the WasmStream and its WebSocket callbacks.
struct WasmStreamState {
    read_buf: VecDeque<u8>,
    read_waker: Option<Waker>,
    error: Option<String>,
    closed: bool,
}

/// Prevent closures from being dropped (must live as long as the WebSocket).
struct WasmClosures {
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::ErrorEvent)>,
    _onclose: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

/// WebSocket-backed async byte stream for WASM.
///
/// Incoming binary frames are buffered and surfaced via `AsyncRead`.
/// Outgoing bytes are sent as binary WebSocket messages via `AsyncWrite`.
pub struct WasmStream {
    ws: web_sys::WebSocket,
    state: Arc<std::sync::Mutex<WasmStreamState>>,
    _closures: WasmClosures,
}

// SAFETY: WASM is single-threaded. web_sys types are !Send/!Sync but there is
// only one thread, so these impls are sound. This is the standard pattern for
// WASM crates that need to satisfy Send/Sync bounds.
unsafe impl Send for WasmStream {}
unsafe impl Sync for WasmStream {}

impl Unpin for WasmStream {}

impl WasmStream {
    /// Open a WebSocket connection to the given URL.
    ///
    /// Awaits the WebSocket `open` event before returning.
    /// Returns an error if the connection fails or the `error` event fires first.
    async fn connect(url: &str) -> io::Result<Self> {
        let ws = web_sys::WebSocket::new(url)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let state = Arc::new(std::sync::Mutex::new(WasmStreamState {
            read_buf: VecDeque::new(),
            read_waker: None,
            error: None,
            closed: false,
        }));

        // Channel to await connection open or error
        let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
        let open_tx = Arc::new(std::sync::Mutex::new(Some(open_tx)));

        // onopen: signal connection success
        let tx_open = open_tx.clone();
        let onopen = Closure::once(move || {
            if let Some(tx) = tx_open.lock().unwrap().take() {
                let _ = tx.send(Ok(()));
            }
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        // Leak the one-shot closure — it fires once, then the browser GCs the ref.
        onopen.forget();

        // onmessage: buffer incoming binary data
        let state_msg = state.clone();
        let onmessage = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
            if let Ok(abuf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let array = js_sys::Uint8Array::new(&abuf);
                let bytes = array.to_vec();
                let mut s = state_msg.lock().unwrap();
                s.read_buf.extend(bytes);
                if let Some(waker) = s.read_waker.take() {
                    waker.wake();
                }
            }
        }) as Box<dyn FnMut(web_sys::MessageEvent)>);
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        // onerror: record error, wake readers, signal connection failure if still pending
        let state_err = state.clone();
        let tx_err = open_tx.clone();
        let onerror = Closure::wrap(Box::new(move |_: web_sys::ErrorEvent| {
            let mut s = state_err.lock().unwrap();
            s.error = Some("WebSocket error".to_string());
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
            if let Some(tx) = tx_err.lock().unwrap().take() {
                let _ = tx.send(Err("WebSocket error".to_string()));
            }
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        // onclose: mark closed, wake readers
        let state_close = state.clone();
        let onclose = Closure::wrap(Box::new(move |_: web_sys::CloseEvent| {
            let mut s = state_close.lock().unwrap();
            s.closed = true;
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::CloseEvent)>);
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        // Await connection open or error
        match open_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "WebSocket open channel dropped",
                ));
            }
        }

        Ok(Self {
            ws,
            state,
            _closures: WasmClosures {
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
        })
    }
}

impl Drop for WasmStream {
    fn drop(&mut self) {
        // Clear callbacks to avoid calling into freed closures
        self.ws.set_onmessage(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}

impl AsyncRead for WasmStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();

        if !state.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), state.read_buf.len());
            let data: Vec<u8> = state.read_buf.drain(..to_read).collect();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        if state.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        if let Some(ref e) = state.error {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.clone())));
        }

        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for WasmStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let state = self.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket closed",
            )));
        }
        if let Some(ref e) = state.error {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.clone())));
        }
        drop(state);

        self.ws
            .send_with_u8_array(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.ws.close();
        Poll::Ready(Ok(()))
    }
}

/// WASM listener — client-only; never yields connections.
pub struct WasmListener;

impl futures::Stream for WasmListener {
    type Item = io::Result<(WasmStream, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Unpin for WasmListener {}

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

/// Client configuration for WASM WebSocket transport.
#[derive(Clone, Debug)]
pub struct WasmClientConfig {
    /// Use `wss://` (true) or `ws://` (false).
    pub use_tls: bool,
}

#[derive(Clone, Debug)]
pub struct WasmOrderedReliableConfig;
#[derive(Clone, Debug)]
pub struct WasmSecureConfig;
#[derive(Clone, Debug)]
pub struct WasmP2PConfig;

/// Wrapper asserting a future is `Send`.
///
/// SAFETY: Sound only when the future will never be transferred between threads.
/// WASM is single-threaded, so this invariant always holds.
struct SendFuture<F>(F);

// SAFETY: WASM is single-threaded — no cross-thread transfer possible.
unsafe impl<F> Send for SendFuture<F> {}

impl<F: Future> Future for SendFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: Structural pinning — the outer Pin guarantees SendFuture won't
        // move, so the inner F (at a fixed offset) also won't move.
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll(cx)
    }
}

impl super::platform_ops::PlatformOps for WasmIO {
    #[allow(clippy::too_many_arguments)]
    fn p2p_hole_punch<R: citadel_crypt::ratchets::Ratchet>(
        session: crate::proto::session::CitadelSession<R, Self>,
        peer_connection_type: crate::proto::peer::peer_layer::PeerConnectionType,
        ticket: crate::proto::remote::Ticket,
        peer_nat_info: crate::proto::peer::peer_crypt::PeerNatInfo,
        channel_signal: crate::proto::node_result::NodeResult<R>,
        hole_punch_compat_stream: crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream<R>,
        endpoint_ratchet: R,
        peer_cid: u64,
        sync_instant: citadel_io::time::Instant,
        node_type: netbeam::sync::RelativeNodeType,
        udp_mode: citadel_types::proto::UdpMode,
        session_security_settings: citadel_types::proto::SessionSecuritySettings,
        cancel_rx: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::NetworkError>>
           + crate::macros::ContextRequirements {
        async move {
            let _ = (
                peer_connection_type,
                ticket,
                peer_nat_info,
                hole_punch_compat_stream,
                endpoint_ratchet,
                peer_cid,
                sync_instant,
                node_type,
                udp_mode,
                session_security_settings,
                cancel_rx,
            );
            session.send_to_kernel(channel_signal)?;
            Ok(())
        }
    }
}

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

    fn connect(
        config: &Self::ClientConfig,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        let use_tls = config.use_tls;
        // SAFETY: WASM is single-threaded. The future captures !Send web_sys
        // closures but they will never be transferred between threads.
        SendFuture(async move {
            let scheme = if use_tls { "wss" } else { "ws" };
            let url = format!("{scheme}://{addr}");
            WasmStream::connect(&url).await
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
        Ok(WasmClientConfig { use_tls: false })
    }

    fn server_identity(_config: &ServerMode<Self>) -> Option<String> {
        None
    }

    fn local_addr(_stream: &Self::Stream) -> io::Result<SocketAddr> {
        // Browser WebSockets don't expose local addr; return a sentinel.
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
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
        // Could extract from the WebSocket URL, but not needed yet.
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
