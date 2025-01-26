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
pub mod net;
pub mod panic_future;
pub mod session_security_settings;
pub mod udp_internal_interface;
pub mod underlying_proto;

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
