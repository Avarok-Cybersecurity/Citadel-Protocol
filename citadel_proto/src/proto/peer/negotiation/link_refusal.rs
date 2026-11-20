//! One refusal of a link to a peer, whichever side this one is: its own dial ends, or the accept
//! it answers is refused.

use super::refusal::{refuse_accept, refuse_attempt};
use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::remote::Ticket;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;

/// Refuses the link to `peer_cid` with `error`: this side's own dial toward the peer, if it
/// holds one, ends and its kernel hears why on the dial's ticket; otherwise the accept it answers
/// is refused. Either way the peer hears it through the server on the exchange's `ticket`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_link<R: Ratchet>(
    state_container: &mut StateContainerInner<R>,
    kernel_tx: &crate::proto::outbound_sender::UnboundedSender<NodeResult<R>>,
    session_cid: u64,
    peer_cid: u64,
    error: String,
    ticket: Ticket,
    sess_ratchet: &R,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    match state_container
        .outgoing_peer_connect_attempts
        .remove(&peer_cid)
    {
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
    }
}
