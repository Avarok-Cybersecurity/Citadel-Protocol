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

use crate::proto::packet::HdpHeader;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::state_container::VirtualConnectionType;
use bytes::BytesMut;
use std::fmt::Formatter;

pub mod includes {
    pub use std::net::SocketAddr;

    pub use citadel_io::time::{Duration, Instant};
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
pub(crate) mod recover_packet;
pub mod register_packet;
pub(crate) mod server_probe_packet;
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
    /// A response packet should be sent back to the sender, terminating the session soon thereafter
    EndSessionAndReplyToSender(BytesMut, &'static str),
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
            PrimaryProcessorResult::EndSessionAndReplyToSender(packet, reason) => {
                write!(
                    f,
                    "PrimaryProcessorResult::EndSessionAndReplyToSender(len: {}, {reason})",
                    packet.len()
                )
            }
        }
    }
}

/// should only be called by the receiver of a packet
/// The session and target CIDs `packet`'s header names, for a processor's tracing fields.
/// `None` for a packet too short to hold a header: those fields unwrapped the parse, so a
/// truncated packet panicked the processor before it could be refused (S-C6).
#[cfg(feature = "localhost-testing")]
pub(crate) fn header_cids(packet: &crate::proto::packet::HdpPacket) -> (Option<u64>, Option<u64>) {
    packet
        .parse()
        .map(|(header, _)| (header.session_cid.get(), header.target_cid.get()))
        .unzip()
}

#[cfg(all(test, feature = "localhost-testing"))]
mod header_cids_tests {
    use super::header_cids;
    use crate::proto::packet::{HdpHeader, HdpPacket};
    use bytes::BytesMut;

    #[test]
    fn a_packet_too_short_for_a_header_has_no_cids() {
        let short =
            HdpPacket::new_recv(BytesMut::from(&[7u8; 3][..]), ([127, 0, 0, 1], 1).into(), 1);
        assert_eq!(header_cids(&short), (None, None));
        let whole = HdpPacket::new_recv(
            BytesMut::zeroed(std::mem::size_of::<HdpHeader>()),
            ([127, 0, 0, 1], 1).into(),
            1,
        );
        assert_eq!(header_cids(&whole), (Some(0), Some(0)));
    }
}

pub(crate) fn header_to_response_vconn_type(header: &HdpHeader) -> VirtualConnectionType {
    let session_cid = header.session_cid.get();
    let target_cid = header.target_cid.get();
    if target_cid != C2S_IDENTITY_CID {
        // the peer_cid and implicated cid must be flipped
        VirtualConnectionType::LocalGroupPeer {
            session_cid: target_cid,
            peer_cid: session_cid,
        }
    } else {
        VirtualConnectionType::LocalGroupServer { session_cid }
    }
}
