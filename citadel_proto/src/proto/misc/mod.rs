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
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod direct_frame_writer;
pub mod dual_cell;
pub mod dual_late_init;
pub mod dual_rwlock;
pub mod lock_holder;
pub mod panic_future;
pub mod session_security_settings;

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
pub(crate) mod native_io_udp;
#[cfg(not(target_family = "wasm"))]
pub mod native_upgrade;
#[cfg(not(target_family = "wasm"))]
pub mod native_websocket;
#[cfg(not(target_family = "wasm"))]
pub mod net;
pub(crate) mod platform_ops;
pub(crate) mod threading;
pub mod udp_internal_interface;
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
pub(crate) mod wasm_rtc;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm_stream;

/// The copy-free writer half of a split primary stream (see [`DirectFrameWriter`]).
pub type PrimaryStreamWriter<S> = DirectFrameWriter<WriteHalf<S>>;
/// The length-delimited reader half of a split primary stream.
pub type PrimaryStreamReader<S> = FramedRead<ReadHalf<S>, LengthDelimitedCodec>;

/// Builds the `LengthDelimitedCodec` configuration shared by the reader and the direct
/// writer so both sides agree on the wire framing (SSOT). The writer in
/// `direct_frame_writer.rs` reproduces these exact bytes (`u32` big-endian length prefix,
/// no adjustment) without going through the codec's encode buffer.
fn primary_stream_codec_builder() -> citadel_io::tokio_util::codec::length_delimited::Builder {
    let mut builder = LengthDelimitedCodec::builder();
    builder
        .length_field_offset(0)
        .max_frame_length(1024 * 1024 * 64) // 64 MB
        .length_field_type::<u32>()
        .length_adjustment(0);
    builder
}

/// Splits a stream into a copy-free direct writer and a length-delimited reader. The
/// writer writes the length frame and body directly to the socket, bypassing the codec
/// encode copy; the reader keeps the standard `LengthDelimitedCodec`. Dropping the writer
/// gracefully shuts down the write half (TLS close_notify / TCP FIN).
#[doc(hidden)]
pub fn safe_split_stream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements + 'static>(
    stream: S,
) -> (PrimaryStreamWriter<S>, PrimaryStreamReader<S>) {
    let (read_half, write_half) = split(stream);
    let reader = primary_stream_codec_builder().new_read(read_half);
    let writer = DirectFrameWriter::new(write_half);
    (writer, reader)
}

pub async fn read_one_packet_as_framed<S: AsyncRead + Unpin, D: DeserializeOwned + Serialize>(
    io: S,
) -> Result<(S, D), NetworkError> {
    let mut framed = LengthDelimitedCodec::builder().new_read(io);
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
    framed
        .flush()
        .await
        .map_err(|err| NetworkError::generic(err.to_string()))?;
    Ok(framed.into_inner())
}
