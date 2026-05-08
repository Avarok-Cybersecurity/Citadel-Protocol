//! Standard Network Protocol Components
//!
//! This module provides core networking components and utilities that form the
//! foundation of the Citadel Protocol's network stack.

#[cfg(not(target_family = "wasm"))]
pub mod misc;
pub mod nat_identification;
#[cfg(not(target_family = "wasm"))]
pub mod quic;
#[cfg(not(target_family = "wasm"))]
pub mod socket_helpers;
#[cfg(not(target_family = "wasm"))]
pub mod tls;
#[cfg(not(target_family = "wasm"))]
pub mod upnp_handler;
