//! Miscellaneous Utilities for Citadel Protocol
//!
//! This module provides various utility types and functions used throughout the
//! Citadel Protocol implementation. It includes thread-safe containers, network
//! utilities, and resource management tools.
//!
//! # Features
//!
//! - Thread-safe data structures
//! - Network utility functions
//! - Resource management tools
//! - Async utilities
//! - Protocol type definitions
//!
//! # Important Notes
//!
//! - Supports both single and multi-threaded operation
//! - Provides zero-cost abstractions
//! - Ensures proper resource cleanup
//! - Maintains thread safety guarantees
//!
//! # Related Components
//!
//! - `proto/node.rs`: Network node implementation
//! - `proto/session.rs`: Session management
//! - `kernel/mod.rs`: Kernel implementation
//! - `error.rs`: Error handling

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use crate::proto::misc::direct_frame_writer::DirectFrameWriter;
use bytes::Bytes;
use citadel_io::tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use citadel_io::tokio_stream::StreamExt;
use citadel_io::tokio_util::codec::{FramedRead, LengthDelimitedCodec};
use citadel_io::{error, ErrorCode};
use futures::SinkExt;
use primary_frame::{PrimaryFrameDecoder, MAX_PRIMARY_FRAME_LEN};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod direct_frame_writer;
pub mod dual_cell;
pub mod dual_late_init;
pub mod dual_rwlock;
pub mod lock_holder;
pub mod panic_future;
pub mod primary_frame;
#[cfg(all(test, not(target_family = "wasm")))]
mod primary_frame_tests;
pub mod session_security_settings;

/// `citadel_wire` returns `anyhow::Error`. Converting it with `err.to_string()`
/// destroys the errno AND the kind, so callers cannot distinguish
/// "address in use" from "permission denied", or a connect timeout from a
/// refusal, without parsing English. The underlying `io::Error` is still in the
/// anyhow chain — recover it, and fall back to `fallback` only for errors that
/// genuinely did not originate from the OS.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn io_error_from_anyhow(
    err: anyhow::Error,
    fallback: std::io::ErrorKind,
) -> std::io::Error {
    match err.downcast::<std::io::Error>() {
        Ok(io_err) => io_err,
        Err(other) => std::io::Error::new(fallback, other.to_string()),
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) mod accept_loop;
pub mod local_rebind;
#[cfg(not(target_family = "wasm"))]
pub mod native_bind;
#[cfg(not(target_family = "wasm"))]
pub mod native_config;
#[cfg(not(target_family = "wasm"))]
pub mod native_connect;
#[cfg(not(target_family = "wasm"))]
pub mod native_io;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod native_io_platform;
#[cfg(not(target_family = "wasm"))]
pub mod native_upgrade;
#[cfg(not(target_family = "wasm"))]
pub mod native_websocket;
#[cfg(not(target_family = "wasm"))]
pub mod native_ws_connect;
#[cfg(not(target_family = "wasm"))]
pub mod native_ws_transport;
#[cfg(not(target_family = "wasm"))]
pub mod net;
pub(crate) mod platform_ops;
pub(crate) mod server_endpoint_store;
pub(crate) mod threading;
pub mod udp_internal_interface;
pub(crate) mod udp_restored;
pub(crate) mod udp_session_loader;
pub(crate) mod udp_session_tasks;
pub mod ws_ping;
// StateContainer lock-contention profiling. Compiled only under the opt-in `lock-profiling` feature;
// the `inner_state!`/`inner_mut_state!` macros feed it. Diagnostics/benches only.
#[cfg(feature = "lock-profiling")]
pub mod lock_profiling;

#[cfg(target_family = "wasm")]
pub mod serverless;
#[cfg(target_family = "wasm")]
pub mod signaling;
#[cfg(target_family = "wasm")]
pub mod signaling_firebase;
#[cfg(target_family = "wasm")]
pub mod wasm_io;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_p2p;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_p2p_established;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_p2p_signaling;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_promise;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_rtc;
#[cfg(target_family = "wasm")]
pub mod wasm_stream;

/// The copy-free writer half of a split primary stream (see [`DirectFrameWriter`]).
pub type PrimaryStreamWriter<S> = DirectFrameWriter<WriteHalf<S>>;
/// The length-delimited reader half of a split primary stream.
pub type PrimaryStreamReader<S> = FramedRead<ReadHalf<S>, PrimaryFrameDecoder>;

/// The primary stream's frame reader over `io`. The writer in `direct_frame_writer.rs` writes
/// the same frames (see [`primary_frame`]).
fn primary_stream_reader<Io: AsyncRead>(io: Io) -> FramedRead<Io, PrimaryFrameDecoder> {
    FramedRead::new(io, PrimaryFrameDecoder::new(MAX_PRIMARY_FRAME_LEN))
}

/// The largest first packet a client reads from a server: a [`net::FirstPacket`] carries at most
/// a domain name (253 bytes) and an address, so 4 KiB is over ten times the largest one.
#[cfg(not(target_family = "wasm"))]
pub const MAX_FIRST_PACKET_LEN: usize = 4 * 1024;

/// Splits a stream into a copy-free direct writer and a length-delimited reader. The
/// writer writes the length frame and body directly to the socket, bypassing the codec
/// encode copy; the reader is a [`PrimaryFrameDecoder`]. Dropping the writer
/// gracefully shuts down the write half (TLS close_notify / TCP FIN).
#[doc(hidden)]
pub fn safe_split_stream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements + 'static>(
    stream: S,
) -> (PrimaryStreamWriter<S>, PrimaryStreamReader<S>) {
    let (read_half, write_half) = split(stream);
    let reader = primary_stream_reader(read_half);
    let writer = DirectFrameWriter::new(write_half);
    (writer, reader)
}

/// Reads one frame of at most `max_len` bytes from `io` and decodes it as a `D`.
pub async fn read_one_packet_as_framed<S: AsyncRead + Unpin, D: DeserializeOwned + Serialize>(
    io: S,
    max_len: usize,
) -> Result<(S, D), NetworkError> {
    let mut framed = FramedRead::new(io, PrimaryFrameDecoder::new(max_len));
    let packet = framed
        .next()
        .await
        .ok_or_else(|| error!(ErrorCode::FirstPacketUnavailable))??;
    let deser = citadel_user::serialization::SyncIO::deserialize_from_vector(&packet)
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    Ok((framed.into_inner(), deser))
}

pub async fn write_one_packet<S: AsyncWrite + Unpin, R: Into<Bytes>>(
    io: S,
    packet: R,
) -> Result<S, NetworkError> {
    let packet = packet.into();
    let mut framed = LengthDelimitedCodec::builder().new_write(io);
    framed
        .send(packet.clone())
        .await
        .map_err(|err| NetworkError::generic(err.to_string()))?;
    // tokio-util 0.7.20 also encodes `&[u8]`, so the item a flush is for must be named.
    SinkExt::<Bytes>::flush(&mut framed)
        .await
        .map_err(|err| NetworkError::generic(err.to_string()))?;
    Ok(framed.into_inner())
}
