//! Async byte streams for WASM targets.
//!
//! [`WasmStream`] is an enum over two transports:
//! - [`WasmWebSocketStream`]: browser WebSocket (C2S connections)
//! - [`WasmDataChannelStream`]: WebRTC DataChannel (P2P connections)
//!
//! Both implement `AsyncRead + AsyncWrite` using the same buffered-callback
//! pattern, allowing the protocol layer to be transport-agnostic.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_io::tokio::sync::oneshot;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

// ── Shared buffered state ────────────────────────────────────────────

/// Shared read buffer + waker, used by both WebSocket and DataChannel streams.
pub(crate) struct WasmStreamState {
    pub read_buf: VecDeque<u8>,
    pub read_waker: Option<Waker>,
    pub error: Option<String>,
    pub closed: bool,
}

impl WasmStreamState {
    pub fn new() -> Self {
        Self {
            read_buf: VecDeque::new(),
            read_waker: None,
            error: None,
            closed: false,
        }
    }
}

/// Poll helper: drain buffered bytes or return Pending/EOF/Error.
fn poll_read_from_state(
    state: &Arc<std::sync::Mutex<WasmStreamState>>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    let mut s = s_lock(state);

    if !s.read_buf.is_empty() {
        let to_read = std::cmp::min(buf.remaining(), s.read_buf.len());
        let data: Vec<u8> = s.read_buf.drain(..to_read).collect();
        buf.put_slice(&data);
        return Poll::Ready(Ok(()));
    }

    if s.closed {
        return Poll::Ready(Ok(())); // EOF
    }

    if let Some(ref e) = s.error {
        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.clone())));
    }

    s.read_waker = Some(cx.waker().clone());
    Poll::Pending
}

/// Poll helper: check closed/error before writing.
fn check_write_state(state: &Arc<std::sync::Mutex<WasmStreamState>>) -> io::Result<()> {
    let s = s_lock(state);
    if s.closed {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
    }
    if let Some(ref e) = s.error {
        return Err(io::Error::new(io::ErrorKind::Other, e.clone()));
    }
    Ok(())
}

fn s_lock(
    state: &Arc<std::sync::Mutex<WasmStreamState>>,
) -> std::sync::MutexGuard<'_, WasmStreamState> {
    state.lock().unwrap()
}

// ── WasmStream enum ─────────────────────────────────────────────────

/// Async byte stream for WASM — dispatches to WebSocket or DataChannel.
pub enum WasmStream {
    WebSocket(WasmWebSocketStream),
    DataChannel(WasmDataChannelStream),
}

// SAFETY: WASM is single-threaded. web_sys types are !Send/!Sync but there is
// only one thread, so these impls are sound.
unsafe impl Send for WasmStream {}
unsafe impl Sync for WasmStream {}
impl Unpin for WasmStream {}

impl AsyncRead for WasmStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::WebSocket(ws) => Pin::new(ws).poll_read(cx, buf),
            Self::DataChannel(dc) => Pin::new(dc).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WasmStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::WebSocket(ws) => Pin::new(ws).poll_write(cx, buf),
            Self::DataChannel(dc) => Pin::new(dc).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::WebSocket(ws) => Pin::new(ws).poll_flush(cx),
            Self::DataChannel(dc) => Pin::new(dc).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::WebSocket(ws) => Pin::new(ws).poll_shutdown(cx),
            Self::DataChannel(dc) => Pin::new(dc).poll_shutdown(cx),
        }
    }
}

// ── WebSocket stream ────────────────────────────────────────────────

/// Prevent closures from being dropped (must live as long as the WebSocket).
struct WsClosures {
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::ErrorEvent)>,
    _onclose: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

/// WebSocket-backed async byte stream.
///
/// Incoming binary frames are buffered and surfaced via `AsyncRead`.
/// Outgoing bytes are sent as binary WebSocket messages via `AsyncWrite`.
pub struct WasmWebSocketStream {
    ws: web_sys::WebSocket,
    state: Arc<std::sync::Mutex<WasmStreamState>>,
    _closures: WsClosures,
}

unsafe impl Send for WasmWebSocketStream {}
unsafe impl Sync for WasmWebSocketStream {}
impl Unpin for WasmWebSocketStream {}

impl WasmWebSocketStream {
    /// Open a WebSocket connection to the given URL.
    ///
    /// Awaits the WebSocket `open` event before returning.
    pub async fn connect(url: &str) -> io::Result<Self> {
        let ws = web_sys::WebSocket::new(url)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let state = Arc::new(std::sync::Mutex::new(WasmStreamState::new()));

        let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
        let open_tx = Arc::new(std::sync::Mutex::new(Some(open_tx)));

        // onopen
        let tx_open = open_tx.clone();
        let onopen = Closure::once(move || {
            if let Some(tx) = tx_open.lock().unwrap().take() {
                let _ = tx.send(Ok(()));
            }
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        // onmessage
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

        // onerror
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

        // onclose
        let state_close = state.clone();
        let onclose = Closure::wrap(Box::new(move |_: web_sys::CloseEvent| {
            let mut s = state_close.lock().unwrap();
            s.closed = true;
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::CloseEvent)>);
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        match open_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e)),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "WebSocket open channel dropped",
                ))
            }
        }

        Ok(Self {
            ws,
            state,
            _closures: WsClosures {
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
        })
    }
}

impl Drop for WasmWebSocketStream {
    fn drop(&mut self) {
        self.ws.set_onmessage(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}

impl AsyncRead for WasmWebSocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_from_state(&self.state, cx, buf)
    }
}

impl AsyncWrite for WasmWebSocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        check_write_state(&self.state)?;
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

// ── DataChannel stream ──────────────────────────────────────────────

/// Prevent closures from being dropped (must live as long as the DataChannel).
struct DcClosures {
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::Event)>,
    _onclose: Closure<dyn FnMut(web_sys::Event)>,
}

/// WebRTC DataChannel-backed async byte stream.
///
/// Uses an ordered, reliable DataChannel for TCP-like semantics.
/// Keeps the parent `RtcPeerConnection` alive via `Arc`.
pub struct WasmDataChannelStream {
    dc: web_sys::RtcDataChannel,
    state: Arc<std::sync::Mutex<WasmStreamState>>,
    _closures: DcClosures,
    /// Prevent the peer connection from being GC'd while the stream is alive.
    _peer_connection: Arc<web_sys::RtcPeerConnection>,
}

unsafe impl Send for WasmDataChannelStream {}
unsafe impl Sync for WasmDataChannelStream {}
impl Unpin for WasmDataChannelStream {}

impl WasmDataChannelStream {
    /// Wrap an already-open `RtcDataChannel` into an async stream.
    ///
    /// The DataChannel must already be in the `open` state (or about to be).
    /// The caller should use [`super::wasm_rtc::wait_for_datachannel_open`]
    /// before constructing this.
    pub fn new(
        dc: web_sys::RtcDataChannel,
        peer_connection: Arc<web_sys::RtcPeerConnection>,
    ) -> Self {
        dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

        let state = Arc::new(std::sync::Mutex::new(WasmStreamState::new()));

        // onmessage
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
        dc.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        // onerror
        let state_err = state.clone();
        let onerror = Closure::wrap(Box::new(move |_: web_sys::Event| {
            let mut s = state_err.lock().unwrap();
            s.error = Some("DataChannel error".to_string());
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        dc.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        // onclose
        let state_close = state.clone();
        let onclose = Closure::wrap(Box::new(move |_: web_sys::Event| {
            let mut s = state_close.lock().unwrap();
            s.closed = true;
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        dc.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        Self {
            dc,
            state,
            _closures: DcClosures {
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
            _peer_connection: peer_connection,
        }
    }
}

impl Drop for WasmDataChannelStream {
    fn drop(&mut self) {
        self.dc.set_onmessage(None);
        self.dc.set_onerror(None);
        self.dc.set_onclose(None);
        self.dc.close();
    }
}

impl AsyncRead for WasmDataChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_from_state(&self.state, cx, buf)
    }
}

impl AsyncWrite for WasmDataChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        check_write_state(&self.state)?;
        self.dc
            .send_with_u8_array(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.dc.close();
        Poll::Ready(Ok(()))
    }
}

// ── SendFuture ──────────────────────────────────────────────────────

/// Wrapper asserting a future is `Send`.
///
/// SAFETY: Sound only when the future will never be transferred between threads.
/// WASM is single-threaded, so this invariant always holds.
pub(crate) struct SendFuture<F>(pub F);

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
