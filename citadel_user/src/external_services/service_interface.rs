//! # External Service Interface
//!
//! This module defines the core interface for external service communication in the Citadel Protocol.
//! It provides a unified way to interact with various external services through a common trait.
//!
//! ## Features
//!
//! * Common interface for external services
//! * Asynchronous data transmission
//! * Error handling with AccountError
//! * Raw packet data support
//! * Peer-to-peer communication
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use citadel_user::external_services::service_interface::{ExternalServiceChannel, RawExternalPacket};
//! use async_trait::async_trait;
//!
//! struct MyService;
//!
//! #[async_trait]
//! impl ExternalServiceChannel for MyService {
//!     async fn send(
//!         &mut self,
//!         data: RawExternalPacket,
//!         session_cid: u64,
//!         peer_cid: u64,
//!     ) -> Result<(), AccountError> {
//!         // Implement service-specific send logic
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Implementations must be thread-safe
//! * Services should handle reconnection
//! * Error handling is standardized
//! * Data format is raw bytes
//!
//! ## Related Components
//!
//! * `RawExternalPacket`: Data packet type
//! * `AccountError`: Error handling type
//! * `async_trait`: Async trait support
//!

use crate::misc::AccountError;
use async_trait::async_trait;

/// The default type for transmitting data
pub type RawExternalPacket = Vec<u8>;

#[async_trait]
/// An interface for unifying interaction with underlying services
pub trait ExternalServiceChannel {
    /// Sends a payload from `session_cid` to `peer_cid`
    async fn send(
        &mut self,
        data: RawExternalPacket,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<(), AccountError>;
}
