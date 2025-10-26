//! # Citadel Protocol Core Implementation
//!
//! This module implements the core networking and protocol functionality of the Citadel Protocol.
//! It provides a comprehensive set of components for secure communication, session management,
//! and packet processing.
//!
//! ## Features
//! - **Session Management**: Handles connection lifecycles and state
//! - **Packet Processing**: Efficient packet encoding, validation, and routing
//! - **Security**: Implements encryption, key rotation, and validation
//! - **Peer Communication**: Manages peer-to-peer and group channels
//! - **State Management**: Tracks connection and operation states
//!
//! ## Module Structure
//! - `codec`: Custom BytesCodec implementation
//! - `node`: Core HyperNode implementation
//! - `packet`: Fundamental packet types and processing
//! - `peer`: Peer-to-peer communication layer
//! - `session`: Connection session management
//! - `validation`: Packet validation and security
//!
//! ## Important Notes
//! - All packet processing is inlined for performance
//! - Session management is CID-based
//! - State containers handle different protocol stages
//! - Transfer stats track performance metrics
//!
//! ## Related Components
//! - `citadel_crypt`: Provides cryptographic primitives
//! - `citadel_wire`: Handles low-level networking
//! - `citadel_types`: Common type definitions
//! - `citadel_user`: User management and authentication
//!

use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::packet::HdpHeader;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;

/// For the custom BytesCodec that doesn't overflow
pub(crate) mod codec;
pub(crate) mod endpoint_crypto_accessor;
pub(crate) mod misc;
/// Used at each HyperNode
pub mod node;
pub mod node_request;
pub mod node_result;
/// A cloneable handle for sending data through UDP ports
pub(crate) mod outbound_sender;
/// The fundamental packet types
pub(crate) mod packet;
/// For creating specific packet types
pub(crate) mod packet_crafter;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub(crate) mod packet_processor;
pub(crate) mod peer;
pub mod remote;
/// Each CID gets a session
pub(crate) mod session;
/// Manages multiple sessions
pub(crate) mod session_manager;
pub(crate) mod session_queue_handler;
/// For keeping track of the stages of different processes
pub(crate) mod state_container;
/// For organizing the stage containers
pub(crate) mod state_subcontainers;
/// ~!
pub(crate) mod transfer_stats;
/// Packet validations. This is not the same as encryption
pub(crate) mod validation;

/// Returns the preferred primary stream for returning a response
pub(crate) fn get_preferred_primary_stream<R: Ratchet>(
    header: &HdpHeader,
    session: &CitadelSession<R>,
    state_container: &StateContainerInner<R>,
) -> Option<OutboundPrimaryStreamSender> {
    if header.target_cid.get() != 0 {
        state_container
            .get_preferred_stream(header.session_cid.get())
            .cloned()
    } else {
        session.to_primary_stream.clone()
    }
}

pub(crate) fn send_with_error_logging(stream: &OutboundPrimaryStreamSender, packet: BytesMut) {
    if let Err(err) = stream.unbounded_send(packet) {
        log::error!(target: "citadel", "Error while sending packet outbound: {err:?}")
    }
}
