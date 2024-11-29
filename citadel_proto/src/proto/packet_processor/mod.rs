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

/// Allows the [HdpSession] to read results from the packet processor herein
#[derive(PartialEq)]
pub enum PrimaryProcessorResult {
    /// Do nothing
    Void,
    EndSession(&'static str),
    /// Returns some data to the sender
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
            implicated_cid: target_cid,
            peer_cid: session_cid,
        }
    } else {
        VirtualConnectionType::LocalGroupServer {
            implicated_cid: session_cid,
        }
    }
}
