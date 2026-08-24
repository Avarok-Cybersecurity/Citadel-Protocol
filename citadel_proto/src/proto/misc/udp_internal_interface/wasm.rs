//! WASM `UdpSplittableTypes`: an unordered, zero-retransmit WebRTC DataChannel (the browser
//! equivalent of UDP datagrams).

use super::{UdpSink, UdpSplittable, UdpStream};
use bytes::{Bytes, BytesMut};
use citadel_io::NetworkError;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use futures::{Sink, Stream};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// SCTP caps a single DataChannel message; anything at or below this is delivered as one unit.
pub(crate) const WEBRTC_MAX_DATAGRAM_LEN: usize = u16::MAX as usize;

// `pub` for the same reason as the native variant: it is surfaced by the public `PlatformOps`
// trait and a crate-private type cannot leak through a public interface (E0446).
pub enum UdpSplittableTypes {
    WebRtc(WebRtcDataChannelConnector),
}

impl UdpSplittableTypes {
    pub fn split(self) -> (Box<dyn UdpSink>, Box<dyn UdpStream>) {
        match self {
            Self::WebRtc(dc) => {
                let (sink, stream) = dc.split_sink_stream();
                (Box::new(sink), Box::new(stream))
            }
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::WebRtc(dc) => dc.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> TargettedSocketAddr {
        match self {
            Self::WebRtc(dc) => dc.peer_addr,
        }
    }

    /// WebRTC DataChannels don't need manual keep-alives (ICE handles it).
    pub(crate) fn needs_manual_ka(&self) -> bool {
        false
    }

    pub(crate) fn max_datagram_len(&self) -> Result<usize, NetworkError> {
        Ok(WEBRTC_MAX_DATAGRAM_LEN)
    }
}

/// Wraps a WebRTC `RtcDataChannel` configured in unordered mode
/// (the browser equivalent of UDP datagrams).
pub struct WebRtcDataChannelConnector {
    sink: DataChannelSink,
    stream: DataChannelStream,
    local_addr: SocketAddr,
    peer_addr: TargettedSocketAddr,
}

// SAFETY: WASM is single-threaded; web_sys types are !Send but can never
// actually cross threads.
#[allow(unsafe_code)]
unsafe impl Send for WebRtcDataChannelConnector {}
#[allow(unsafe_code)]
unsafe impl Sync for WebRtcDataChannelConnector {}

impl WebRtcDataChannelConnector {
    /// Create from an already-open `RtcDataChannel`.
    ///
    /// The caller is responsible for ICE negotiation and ensuring the channel
    /// is in the `Open` state before calling this.
    pub fn new(
        dc: web_sys::RtcDataChannel,
        local_addr: SocketAddr,
        peer_addr: TargettedSocketAddr,
    ) -> Self {
        // onmessage must deliver ArrayBuffer, not Blob.
        dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

        let state = Arc::new(std::sync::Mutex::new(DataChannelState {
            recv_buf: VecDeque::new(),
            waker: None,
            error: None,
            closed: false,
        }));

        // onmessage: buffer incoming datagrams
        let state_msg = state.clone();
        let onmessage = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
            if let Ok(abuf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let array = js_sys::Uint8Array::new(&abuf);
                let bytes = array.to_vec();
                let mut s = state_msg.lock().unwrap();
                s.recv_buf.push_back(BytesMut::from(&bytes[..]));
                if let Some(waker) = s.waker.take() {
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
            if let Some(waker) = s.waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        dc.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        // onclose
        let state_close = state.clone();
        let onclose = Closure::wrap(Box::new(move |_: web_sys::Event| {
            let mut s = state_close.lock().unwrap();
            s.closed = true;
            if let Some(waker) = s.waker.take() {
                waker.wake();
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        dc.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        Self {
            sink: DataChannelSink {
                dc: dc.clone(),
                peer_addr: peer_addr.send_address,
            },
            stream: DataChannelStream {
                state,
                peer_addr: peer_addr.send_address,
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
            local_addr,
            peer_addr,
        }
    }
}

impl UdpSplittable for WebRtcDataChannelConnector {
    type Sink = DataChannelSink;
    type Stream = DataChannelStream;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
        (self.sink, self.stream)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

struct DataChannelState {
    recv_buf: VecDeque<BytesMut>,
    waker: Option<std::task::Waker>,
    error: Option<String>,
    closed: bool,
}

pub(crate) struct DataChannelSink {
    dc: web_sys::RtcDataChannel,
    peer_addr: SocketAddr,
}

// SAFETY: WASM is single-threaded.
#[allow(unsafe_code)]
unsafe impl Send for DataChannelSink {}
#[allow(unsafe_code)]
unsafe impl Sync for DataChannelSink {}

pub(crate) struct DataChannelStream {
    state: Arc<std::sync::Mutex<DataChannelState>>,
    peer_addr: SocketAddr,
    // prevent closures from being GC'd
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::Event)>,
    _onclose: Closure<dyn FnMut(web_sys::Event)>,
}

// SAFETY: WASM is single-threaded.
#[allow(unsafe_code)]
unsafe impl Send for DataChannelStream {}
#[allow(unsafe_code)]
unsafe impl Sync for DataChannelStream {}

impl Sink<Bytes> for DataChannelSink {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.dc
            .send_with_u8_array(&item)
            .map_err(|e| NetworkError::generic(format!("{e:?}")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.dc.close();
        Poll::Ready(Ok(()))
    }
}

impl Stream for DataChannelStream {
    type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.state.lock().unwrap();

        if let Some(data) = state.recv_buf.pop_front() {
            return Poll::Ready(Some(Ok((data, self.peer_addr))));
        }

        if state.closed {
            return Poll::Ready(None);
        }

        if let Some(ref e) = state.error {
            return Poll::Ready(Some(Err(std::io::Error::other(e.clone()))));
        }

        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
