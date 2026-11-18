//! A security level read from the wire is checked against this node's maximum before anything is
//! built ([`MaxSecurityLevel`]): every layer is a key exchange and one more seal on every packet,
//! so a peer or a server naming more layers than this node builds is refused, not obeyed.

use super::refusal::{refuse_accept, refuse_attempt};
use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::remote::Ticket;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use citadel_negotiation::RejectReason;
use citadel_types::crypto::{LevelAboveMaximum, MaxSecurityLevel, SecurityLevel};

/// What the refusing side reports to its kernel and to the peer.
pub(crate) fn above_maximum_error(above: LevelAboveMaximum) -> String {
    format!("{:?}: {above}", RejectReason::Unsupported)
}

/// The settings this side is told to build a link to `peer_cid` with (a stamp, an accept, or a
/// key exchange) name a level above `maximum`. The attempt toward the peer ends and the kernel
/// hears why; the peer is refused through the server. `None` when the level is admitted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_if_above_maximum<R: Ratchet>(
    maximum: MaxSecurityLevel,
    stamped: SecurityLevel,
    state_container: &mut StateContainerInner<R>,
    kernel_tx: &crate::proto::outbound_sender::UnboundedSender<NodeResult<R>>,
    session_cid: u64,
    peer_cid: u64,
    ticket: Ticket,
    sess_ratchet: &R,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Option<Result<PrimaryProcessorResult, NetworkError>> {
    let error = above_maximum_error(maximum.check(stamped).err()?);
    let attempt = state_container
        .outgoing_peer_connect_attempts
        .remove(&peer_cid);
    Some(match attempt {
        Some(attempt) => refuse_attempt(
            kernel_tx,
            session_cid,
            peer_cid,
            attempt,
            error,
            ticket,
            sess_ratchet,
            timestamp,
            security_level,
        ),
        None => refuse_accept(
            sess_ratchet,
            session_cid,
            peer_cid,
            ticket,
            error,
            timestamp,
            security_level,
        ),
    })
}
