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
use crate::proto::misc::clean_shutdown::{
    clean_framed_shutdown, CleanShutdownSink, CleanShutdownStream,
};
use bytes::Bytes;
use citadel_io::tokio::io::{AsyncRead, AsyncWrite};
use citadel_io::tokio_stream::StreamExt;
use citadel_io::tokio_util::codec::LengthDelimitedCodec;
use futures::SinkExt;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod clean_shutdown;
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

#[cfg(target_family = "wasm")]
pub mod wasm_io;

/// Wraps a stream into a split interface for I/O that safely shuts-down the interface
/// upon drop
#[doc(hidden)]
pub fn safe_split_stream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements>(
    stream: S,
) -> (
    CleanShutdownSink<S, LengthDelimitedCodec, Bytes>,
    CleanShutdownStream<S, LengthDelimitedCodec, Bytes>,
) {
    let framed = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .max_frame_length(1024 * 1024 * 64) // 64 MB
        .length_field_type::<u32>()
        .length_adjustment(0)
        .new_framed(stream);

    clean_framed_shutdown(framed)
}

pub async fn read_one_packet_as_framed<S: AsyncRead + Unpin, D: DeserializeOwned + Serialize>(
    io: S,
) -> Result<(S, D), NetworkError> {
    let mut framed = LengthDelimitedCodec::builder().new_read(io);
    let packet = framed
        .next()
        .await
        .ok_or_else(|| NetworkError::msg("Unable to get first packet"))??;
    let deser = citadel_user::serialization::SyncIO::deserialize_from_vector(&packet)
        .map_err(|err| NetworkError::Generic(err.into_string()))?;
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
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    framed
        .flush()
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    Ok(framed.into_inner())
}
