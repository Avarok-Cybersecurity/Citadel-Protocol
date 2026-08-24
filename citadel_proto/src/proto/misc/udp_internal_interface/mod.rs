//! UDP Internal Interface
//!
//! Provides the internal interface for UDP communication in the Citadel Protocol.
//! Trait definitions are available on all platforms. Concrete transports: QUIC unreliable
//! datagrams (`quic`) and a hole-punched raw socket (`raw`) on native; an unordered WebRTC
//! DataChannel (`wasm`) in the browser.

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use std::net::SocketAddr;

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

#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(not(target_family = "wasm"))]
mod quic;
#[cfg(not(target_family = "wasm"))]
mod raw;
#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(not(target_family = "wasm"))]
pub(crate) use native::*;
#[cfg(not(target_family = "wasm"))]
pub use quic::QuicUdpSocketConnector;
#[cfg(not(target_family = "wasm"))]
pub use raw::RawUdpSocketConnector;

#[cfg(target_family = "wasm")]
pub(crate) use wasm::*;
