//! Signal Handler Interface for Citadel Protocol
//!
//! This module defines the interface for handling peer signals in the Citadel Protocol
//! network. It provides a trait-based approach for managing signal flow between peers,
//! including outbound sends, server reception, and target reception.
//!
//! # Features
//!
//! - Async signal handling
//! - Outbound signal management
//! - Server signal processing
//! - Target signal reception
//! - Error propagation
//!
//! # Important Notes
//!
//! - Uses async-trait for async operations
//! - Requires implementation for specific signal types
//! - Handles network error propagation
//! - TODO: Structify PeerSignal for implementation
//!
//! # Related Components
//!
//! - `NetworkError`: Error handling
//! - `PeerSignal`: Signal type (pending structification)
//! - `async_trait`: Async trait support

use crate::error::NetworkError;
use async_trait::async_trait;

#[async_trait]
#[allow(dead_code)]
// TODO: 'structify' PeerSignal in order to implement this trait
// for all specific types
pub trait SignalHandler {
    async fn on_local_outbound_send(self) -> Result<(), NetworkError>;
    async fn on_server_received(self) -> Result<(), NetworkError>;
    async fn on_target_received(self) -> Result<(), NetworkError>;
}
