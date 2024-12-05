//! Hole Punch Packet Processor for Citadel Protocol
//!
//! This module implements NAT traversal functionality through hole punching in the
//! Citadel Protocol network. It enables direct peer-to-peer connections between nodes
//! behind NATs by coordinating connection establishment.
//!
//! # Features
//!
//! - NAT traversal packet processing
//! - Secure packet validation
//! - Peer connection coordination
//! - Connection pipe management
//! - Proxy support
//!
//! # Important Notes
//!
//! - Requires valid peer CID
//! - All packets must be authenticated
//! - Manages hole puncher pipes
//! - Supports proxied connections
//! - Forwards validated packets
//!
//! # Related Components
//!
//! - `StateContainer`: Manages hole punch state
//! - `HolePuncherPipe`: Handles connection establishment
//! - `StackedRatchet`: Provides packet security
//! - `ProxyManager`: Handles proxied connections
//!
//! # Example Usage
//!
//! ```no_run
//! use citadel_proto::proto::packet_processor::hole_punch;
//! use citadel_proto::proto::CitadelSession;
//! use citadel_proto::proto::packet::HdpPacket;
//!
//! fn handle_hole_punch(session: &CitadelSession, packet: HdpPacket) {
//!     let hr_version = 1;
//!     let proxy_info = None;
//!     match hole_punch::process_hole_punch(session, packet, hr_version, proxy_info) {
//!         Ok(result) => {
//!             // Handle successful hole punch
//!         }
//!         Err(err) => {
//!             // Handle hole punch error
//!         }
//!     }
//! }
//! ```

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::packet_processor::primary_group_packet::{
    get_orientation_safe_ratchet, get_resp_target_cid_from_header,
};
use citadel_crypt::stacked_ratchet::Ratchet;

/// This will handle an inbound group packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub fn process_hole_punch<R: Ratchet>(
    session: &CitadelSession<R>,
    packet: HdpPacket,
    hr_version: u32,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (header, payload, _, _) = packet.decompose();
    let state_container = inner_state!(session.state_container);
    let hr = return_if_none!(
        get_orientation_safe_ratchet(hr_version, &state_container, proxy_cid_info),
        "Unable to get proper HR"
    );
    let header = header.as_ref();
    let (header, payload) = return_if_none!(
        super::super::validation::aead::validate_custom(&hr, &header, payload),
        "Unable to validate packet"
    );
    log::trace!(target: "citadel", "Success validating hole-punch packet");
    let peer_cid = get_resp_target_cid_from_header(&header);
    return_if_none!(
        return_if_none!(
            state_container.hole_puncher_pipes.get(&peer_cid),
            "Unable to get hole puncher pipe"
        )
        .send(payload.freeze())
        .ok(),
        "Unable to forward hole-punch packet through pipe"
    );
    log::trace!(target: "citadel", "Success forwarding hole-punch packet to hole-puncher");

    Ok(PrimaryProcessorResult::Void)
}
