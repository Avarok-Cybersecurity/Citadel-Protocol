//! # Packet Processor Module
//!
//! Core packet processing infrastructure for the Citadel Protocol, handling all aspects
//! of packet lifecycle from creation to processing.
//!
//! ## Features
//!
//! - **Packet Type Management**: Handles various packet types including:
//!   - Connection establishment packets
//!   - Authentication packets
//!   - Data transfer packets
//!   - Keep-alive packets
//!   - Group communication packets
//!
//! - **Processing Pipeline**:
//!   - Packet validation and verification
//!   - State management during processing
//!   - Error handling and recovery
//!   - Packet queueing and ordering
//!
//! - **Security**:
//!   - Cryptographic verification
//!   - Replay attack prevention
//!   - Packet integrity checks
//!
//! ## Important Notes
//!
//! - All packet processors implement proper error handling
//! - Processors maintain packet ordering guarantees
//! - Implements backpressure mechanisms
//! - Handles partial packet reconstruction
//!
//! ## Related Components
//!
//! - [`connect_packet`]: Connection establishment
//! - [`register_packet`]: Node registration
//! - [`primary_group_packet`]: Group communication
//! - [`peer_cmd_packet`]: Peer commands
//! - [`file_packet`]: File transfer
//! - [`keep_alive_packet`]: Connection maintenance

//! # Citadel Protocol Packet Processing
//!
//! This module implements the core packet processing functionality for the Citadel Protocol.
//! It handles various types of packets including connection establishment, data transfer,
//! group communication, and connection maintenance.
//!
//! ## Packet Types
//!
//! The protocol supports several types of packets:
//!
//! - **Connection Packets**: Handle connection establishment and termination
//!   - `connect_packet`: Connection establishment
//!   - `disconnect_packet`: Connection termination
//!   - `preconnect_packet`: Initial connection setup
//!
//! - **Authentication Packets**:
//!   - `register_packet`: User registration
//!   - `deregister_packet`: User deregistration
//!
//! - **Data Transfer Packets**:
//!   - `file_packet`: File transfer operations
//!   - `primary_group_packet`: Group communication
//!   - `raw_primary_packet`: Raw data transfer
//!
//! - **Maintenance Packets**:
//!   - `keep_alive_packet`: Connection maintenance
//!   - `rekey_packet`: Key rotation
//!   - `hole_punch`: NAT traversal
//!
//! ## Processing Flow
//!
//! 1. Incoming packets are validated and decrypted
//! 2. Packet type is determined from header
//! 3. Packet is processed by appropriate handler
//! 4. Response is generated if needed
//!
//! ## Security
//!
//! - All packets are encrypted using post-quantum cryptography
//! - Headers are protected against tampering
//! - Replay attacks are prevented through sequence numbers
//!
//! ## Example
//!
//! ```no_run
//! use citadel_proto::packet_processor::{PrimaryProcessorResult, HdpPacket};
//!
//! // Process an incoming packet
//! match process_packet(packet) {
//!     PrimaryProcessorResult::Void => { /* No response needed */ }
//!     PrimaryProcessorResult::ReplyToSender(response) => { /* Send response */ }
//!     PrimaryProcessorResult::EndSession(reason) => { /* Handle session end */ }
//! }
//! ```

use crate::proto::packet::HdpHeader;
use crate::proto::packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::proto::state_container::VirtualConnectionType;
use bytes::BytesMut;
use citadel_user::re_exports::__private::Formatter;

pub mod includes {
    pub use std::net::SocketAddr;

    pub use citadel_io::tokio::time::{Duration, Instant};
    pub use log::{trace, warn};
    pub use zerocopy::Ref;

    pub use citadel_types::crypto::SecBuffer;
    pub use citadel_types::crypto::SecurityLevel;

    pub use crate::constants::KEEP_ALIVE_INTERVAL_MS;
    pub use crate::proto::node_result::NodeResult;
    pub(crate) use crate::proto::packet::packet_flags;
    pub use crate::proto::packet::{HdpHeader, HdpPacket};
    pub use crate::proto::session::{CitadelSession, CitadelSessionInner, SessionState};
    pub(crate) use crate::proto::{packet_crafter, validation};

    pub use super::super::state_container::VirtualConnectionType;
    pub use super::PrimaryProcessorResult;
}

pub mod connect_packet;
pub mod deregister_packet;
pub mod disconnect_packet;
pub mod file_packet;
pub mod keep_alive_packet;
pub mod peer;
pub mod preconnect_packet;
pub mod primary_group_packet;
pub mod raw_primary_packet;
pub mod register_packet;
pub mod rekey_packet;
pub mod udp_packet;
//
pub mod hole_punch;

/// Represents the result of processing a primary packet in the Citadel Protocol.
/// This enum is used to communicate the outcome of packet processing back to the
/// session handler.
#[derive(PartialEq)]
pub enum PrimaryProcessorResult {
    /// No action needed after processing the packet
    Void,
    /// Session should be terminated with the given reason
    EndSession(&'static str),
    /// A response packet should be sent back to the sender
    ReplyToSender(BytesMut),
}

impl std::fmt::Debug for PrimaryProcessorResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrimaryProcessorResult::Void => {
                write!(f, "PrimaryProcessorResult::Void")
            }
            PrimaryProcessorResult::EndSession(reason) => {
                write!(f, "PrimaryProcessorResult::EndSession({reason})")
            }
            PrimaryProcessorResult::ReplyToSender(packet) => {
                write!(
                    f,
                    "PrimaryProcessorResult::ReplyToSender(len: {})",
                    packet.len()
                )
            }
        }
    }
}

/// should only be called by the receiver of a packet
pub(crate) fn header_to_response_vconn_type(header: &HdpHeader) -> VirtualConnectionType {
    let session_cid = header.session_cid.get();
    let target_cid = header.target_cid.get();
    if target_cid != C2S_ENCRYPTION_ONLY {
        // the peer_cid and implicated cid must be flipped
        VirtualConnectionType::LocalGroupPeer {
            session_cid: target_cid,
            peer_cid: session_cid,
        }
    } else {
        VirtualConnectionType::LocalGroupServer { session_cid }
    }
}
