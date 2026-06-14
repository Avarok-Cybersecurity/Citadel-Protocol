//! UDP Internal Interface
//!
//! Provides the internal interface for UDP communication in the Citadel Protocol.
//! Trait definitions are available on all platforms; concrete implementations
//! (QUIC, raw UDP) are native-only. On WASM, `UdpSplittableTypes` is uninhabited.

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use bytes::{Bytes, BytesMut};
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use futures::{Sink, Stream};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

// ── Platform-independent trait definitions ──────────────────────────────

// `pub` (not `pub(crate)`): surfaced through `UdpSplittableTypes::split`, which is reachable via the
// public `PlatformOps` trait. A blanket-impl marker trait, so widening visibility is inert.
pub trait UdpSink: Sink<Bytes, Error = NetworkError> + Unpin + ContextRequirements {}
impl<T: Sink<Bytes, Error = NetworkError> + Unpin + ContextRequirements> UdpSink for T {}

pub trait UdpStream:
    Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin + ContextRequirements
{
}
impl<
        T: Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin + ContextRequirements,
    > UdpStream for T
{
}

pub(crate) trait UdpSplittable: ContextRequirements {
    type Sink: UdpSink;
    type Stream: UdpStream;

    fn split_sink_stream(self) -> (Self::Sink, Self::Stream);
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

// ── Native implementation ───────────────────────────────────────────────

#[cfg(not(target_family = "wasm"))]
mod native {
    use super::*;
    use crate::constants::CODEC_BUFFER_CAPACITY;
    use crate::functional::PairMap;
    use crate::proto::codec::BytesCodec;
    use crate::proto::peer::p2p_conn_handler::generic_error;
    use citadel_io::tokio::net::UdpSocket;
    use citadel_io::tokio_util::udp::UdpFramed;
    use citadel_wire::exports::Connection;
    use futures::stream::{SplitSink, SplitStream};
    use futures::StreamExt;

    // `pub` (not `pub(crate)`) because it is exposed through the public `PlatformOps` trait's
    // method signatures; rustc 1.83+ rejects leaking a crate-private type through a public trait
    // (E0446). The variant payload structs are likewise `pub` but keep their fields private.
    pub enum UdpSplittableTypes {
        Quic(QuicUdpSocketConnector),
        Raw(RawUdpSocketConnector),
    }

    impl UdpSplittableTypes {
        pub fn split(self) -> (Box<dyn UdpSink>, Box<dyn UdpStream>) {
            match self {
                Self::Quic(quic) => quic
                    .split_sink_stream()
                    .map_left(|r| Box::new(r) as _)
                    .map_right(|r| Box::new(r) as _),
                Self::Raw(raw) => raw
                    .split_sink_stream()
                    .map_left(|r| Box::new(r) as _)
                    .map_right(|r| Box::new(r) as _),
            }
        }

        pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
            match self {
                Self::Quic(quic) => quic.local_addr(),
                Self::Raw(raw) => raw.local_addr(),
            }
        }

        pub fn peer_addr(&self) -> TargettedSocketAddr {
            match self {
                Self::Quic(quic) => {
                    TargettedSocketAddr::new_invariant(quic.sink.sink.remote_address())
                }
                Self::Raw(raw) => TargettedSocketAddr::new_invariant(raw.sink.peer_addr),
            }
        }

        /// QUIC automatically handles keep alives, RAW UDP does not
        pub(crate) fn needs_manual_ka(&self) -> bool {
            matches!(self, UdpSplittableTypes::Raw(..))
        }
    }

    impl UdpSplittable for QuicUdpSocketConnector {
        type Sink = QuicUdpSendHalf;
        type Stream = QuicUdpRecvHalf;

        fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
            (self.sink, self.stream)
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }
    }

    pub struct QuicUdpSocketConnector {
        pub(super) sink: QuicUdpSendHalf,
        stream: QuicUdpRecvHalf,
        local_addr: SocketAddr,
    }

    impl QuicUdpSocketConnector {
        pub fn new(conn: Connection, local_addr: SocketAddr) -> Self {
            let addr = conn.remote_address();
            let conn_stream = conn.clone();
            let receiver = Box::pin(async_stream::try_stream! {
                loop {
                    yield conn_stream.read_datagram()
                    .await
                    .map(|packet| (BytesMut::from(&packet[..]), addr))
                    .map_err(|err| std::io::Error::other(err.to_string()))?;
                }
            });

            Self {
                sink: QuicUdpSendHalf { sink: conn },
                stream: QuicUdpRecvHalf { receiver },
                local_addr,
            }
        }
    }

    pub(crate) struct QuicUdpSendHalf {
        pub(super) sink: Connection,
    }

    pub(crate) struct QuicUdpRecvHalf {
        receiver: ReceiverStream,
    }

    type ReceiverStream = Pin<
        Box<dyn Stream<Item = Result<(BytesMut, SocketAddr), std::io::Error>> + Send + 'static>,
    >;

    impl Sink<Bytes> for QuicUdpSendHalf {
        type Error = NetworkError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.sink
                .send_datagram(item)
                .map_err(|err| NetworkError::Generic(format!("{err:?}")))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for QuicUdpRecvHalf {
        type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.receiver.as_mut().poll_next(cx)
        }
    }

    impl UdpSplittable for RawUdpSocketConnector {
        type Sink = RawUdpSocketSink;
        type Stream = RawUdpSocketStream;

        fn split_sink_stream(self) -> (Self::Sink, Self::Stream) {
            (self.sink, self.stream)
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.local_addr
                .as_ref()
                .map(|r| *r)
                .map_err(|err| generic_error(format!("{err:?}")))
        }
    }

    pub struct RawUdpSocketConnector {
        sink: RawUdpSocketSink,
        stream: RawUdpSocketStream,
        local_addr: std::io::Result<SocketAddr>,
    }

    impl RawUdpSocketConnector {
        pub fn new(socket: UdpSocket, peer_addr: SocketAddr) -> Self {
            let local_addr = socket.local_addr();

            // Attempt the io_uring recv backend before moving the socket into UdpFramed (it needs to
            // dup the still-borrowed fd). On success the standard recv stream is dropped so io_uring
            // is the sole reader; the send half always stays on the standard path.
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            let io_uring_recv = citadel_io::IoUringUdpReceiver::try_spawn(&socket);

            let framed = UdpFramed::new(socket, BytesCodec::new(CODEC_BUFFER_CAPACITY));
            let (sink, split_stream) = framed.split();

            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            let stream = match io_uring_recv {
                Some(recv) => {
                    log::trace!(target: "citadel", "Raw UDP recv using io_uring backend");
                    drop(split_stream);
                    RawUdpSocketStream::IoUring(recv)
                }
                None => RawUdpSocketStream::Standard(split_stream),
            };
            #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
            let stream = RawUdpSocketStream::Standard(split_stream);

            Self {
                sink: RawUdpSocketSink { sink, peer_addr },
                stream,
                local_addr,
            }
        }
    }

    pub(crate) struct RawUdpSocketSink {
        sink: SplitSink<UdpFramed<BytesCodec>, (Bytes, SocketAddr)>,
        pub(super) peer_addr: SocketAddr,
    }

    // Inbound recv half. Standard tokio path by default; on Linux with the `io-uring` feature and a
    // successful ring init, the io_uring backend (in citadel_io) drives recv instead, while the send
    // half keeps using the standard path. The standard SplitStream is dropped in that case so only
    // one reader consumes the socket.
    pub(crate) enum RawUdpSocketStream {
        Standard(SplitStream<UdpFramed<BytesCodec>>),
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        IoUring(citadel_io::IoUringUdpReceiver),
    }

    impl Sink<Bytes> for RawUdpSocketSink {
        type Error = NetworkError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_ready(cx)
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            let addr = self.peer_addr;
            Pin::new(&mut self.sink)
                .start_send((item, addr))
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_flush(cx)
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_flush(cx)
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }
    }

    impl Stream for RawUdpSocketStream {
        type Item = Result<(BytesMut, SocketAddr), std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match &mut *self {
                RawUdpSocketStream::Standard(stream) => {
                    Pin::new(stream).poll_next(cx).map_err(generic_error)
                }
                #[cfg(all(target_os = "linux", feature = "io-uring"))]
                RawUdpSocketStream::IoUring(recv) => recv.poll_recv(cx),
            }
        }
    }
}

// ── WASM implementation (WebRTC DataChannel) ───────────────────────────

#[cfg(target_family = "wasm")]
mod wasm {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

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
            // Set binaryType to "arraybuffer" so onmessage receives ArrayBuffer, not Blob.
            // web-sys doesn't generate a setter for this property on RtcDataChannel.
            js_sys::Reflect::set(
                &dc,
                &wasm_bindgen::JsValue::from_str("binaryType"),
                &wasm_bindgen::JsValue::from_str("arraybuffer"),
            )
            .expect("failed to set binaryType on RtcDataChannel");

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

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.dc
                .send_with_u8_array(&item)
                .map_err(|e| NetworkError::Generic(format!("{e:?}")))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
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
}

// ── Re-exports ──────────────────────────────────────────────────────────

#[cfg(not(target_family = "wasm"))]
pub(crate) use native::*;

#[cfg(target_family = "wasm")]
pub(crate) use wasm::*;
