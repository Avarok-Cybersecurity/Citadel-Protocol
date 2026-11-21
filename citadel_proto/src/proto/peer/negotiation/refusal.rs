//! A client's refusals around a dial: R-DIAL 3 (never build a link below its own offer), the end
//! of a dial or accept the server refused, an accept for a dial this side no longer holds, and
//! a dial this side will not otherwise answer.

use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::node_result::PeerEvent;
use crate::proto::packet_crafter;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::remote::Ticket;
use crate::proto::state_container::{OutgoingPeerConnectionAttempt, StateContainerInner};
use citadel_crypt::ratchets::Ratchet;
use citadel_negotiation::RejectReason;
use citadel_types::crypto::{PreSharedKey, SecurityLevel};
use citadel_types::proto::{falls_short_of, SessionSecuritySettings, UdpMode};

/// R-DIAL 3. When this side made an offer for the link to `peer_cid` (a dial, or an accept), and
/// the settings it is now told to build with fall short of it, the attempt ends here: it is
/// taken and returned, so the caller refuses. A stamp at or above the offer leaves it in place.
pub(crate) fn take_attempt_stamped_below<R: Ratchet>(
    state_container: &mut StateContainerInner<R>,
    peer_cid: u64,
    stamped: SessionSecuritySettings,
) -> Option<OutgoingPeerConnectionAttempt> {
    let own = state_container
        .outgoing_peer_connect_attempts
        .get(&peer_cid)?
        .session_security_settings;
    if falls_short_of(stamped, own) {
        state_container
            .outgoing_peer_connect_attempts
            .remove(&peer_cid)
    } else {
        None
    }
}

/// What the refusing side reports to its kernel (as `SignalError::error`) and to the peer.
pub(crate) fn below_policy_error(
    stamped: SessionSecuritySettings,
    own: SessionSecuritySettings,
) -> String {
    format!(
        "{:?}: the link was stamped {:?} ({:?}), below this side's own offer {:?} ({:?})",
        RejectReason::BelowPolicy,
        stamped.security_level,
        stamped.secrecy_mode,
        own.security_level,
        own.secrecy_mode
    )
}

/// Refuses a stamp below this side's offer: the kernel hears it on the attempt's ticket (so the
/// dial's caller gets it), and the peer hears it through the server on the exchange's `ticket`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_stamp<R: Ratchet>(
    kernel_tx: &crate::proto::outbound_sender::UnboundedSender<NodeResult<R>>,
    session_cid: u64,
    peer_cid: u64,
    attempt: OutgoingPeerConnectionAttempt,
    stamped: SessionSecuritySettings,
    ticket: Ticket,
    sess_ratchet: &R,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let error = below_policy_error(stamped, attempt.session_security_settings);
    refuse_attempt(
        kernel_tx,
        session_cid,
        peer_cid,
        attempt,
        error,
        ticket,
        sess_ratchet,
        timestamp,
        security_level,
    )
}

/// Ends `attempt` with `error`: the kernel hears it on the attempt's ticket, and the peer hears
/// it through the server on the exchange's `ticket`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_attempt<R: Ratchet>(
    kernel_tx: &crate::proto::outbound_sender::UnboundedSender<NodeResult<R>>,
    session_cid: u64,
    peer_cid: u64,
    attempt: OutgoingPeerConnectionAttempt,
    error: String,
    ticket: Ticket,
    sess_ratchet: &R,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::warn!(target: "citadel", "R-DIAL: refusing the link to {peer_cid}: {error}");
    let toward = |session_cid, peer_cid| PeerConnectionType::LocalGroupPeer {
        session_cid,
        peer_cid,
    };
    kernel_tx
        .unbounded_send(NodeResult::PeerEvent(PeerEvent {
            event: PeerSignal::SignalError {
                ticket: attempt.ticket,
                error: error.clone(),
                peer_connection_type: toward(session_cid, peer_cid),
            },
            ticket: attempt.ticket,
            session_cid,
        }))
        .map_err(|err| NetworkError::msg(err.to_string()))?;
    let to_peer = PeerSignal::SignalError {
        ticket,
        error,
        peer_connection_type: toward(session_cid, peer_cid),
    };
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        sess_ratchet,
        to_peer,
        ticket,
        timestamp,
        security_level,
    )?;
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

/// A refused signal ends the attempt it refused. A dial or an accept is recorded as an attempt
/// when it is sent, and a created channel consumes it; one the server (or the peer) refused must
/// end here too, because the client tiebreak reads that record as "this side is dialling". With
/// it gone, the peer's next dial is put to this side's kernel, whichever side has the lower CID.
pub(crate) fn end_attempt_refused_by<R: Ratchet>(
    state_container: &mut StateContainerInner<R>,
    refusal: &PeerConnectionType,
    refused_ticket: Ticket,
    session_cid: u64,
) {
    let original = refusal.get_original_session_cid();
    let peer_cid = if original == session_cid {
        refusal.get_original_target_cid()
    } else {
        original
    };
    // The server's own refusals (of a crossing's spare accept, which carries the merged
    // exchange's ticket) name this side as the sender; a refusal relayed from the peer names it.
    let from_peer = original != session_cid;
    let refused = state_container
        .outgoing_peer_connect_attempts
        .get(&peer_cid)
        .is_some_and(|attempt| attempt.ticket == refused_ticket);
    if refused {
        log::trace!(target: "citadel", "The attempt toward {peer_cid} on {refused_ticket} was refused; it is no longer an attempt");
        state_container
            .outgoing_peer_connect_attempts
            .remove(&peer_cid);
    }
    // An exchange that ends with the refusal: left in place, it reads as an exchange in progress
    // and turns away the pair's next one. The exchange this side started for a refused attempt
    // ends with it. When the peer refused, so does an exchange this side answered: the one the
    // refusal names, or, when it ended this side's attempt, whichever exchange answered that
    // attempt (a merged crossing's refusal reaches this side on its own dial's ticket).
    let ends = state_container
        .peer_kem_states
        .get(&peer_cid)
        .is_some_and(|kem| {
            let started = kem.local_is_initiator && kem.constructor.is_some();
            let answered = !kem.local_is_initiator && kem.constructor.is_some();
            (refused && started)
                || (from_peer && (kem.answers(refused_ticket) || (refused && answered)))
        });
    if ends && !state_container.has_live_peer_connection(peer_cid) {
        state_container.peer_kem_states.remove(&peer_cid);
    }
}

/// The session password of a dial this side holds toward `peer_cid`: `None` unless a dial (or an
/// accept of the peer's) is in progress and its password is stored. An accept is answered only
/// with it; without one there is no request of ours the accept answers.
pub(crate) fn held_dial_password<R: Ratchet>(
    state_container: &StateContainerInner<R>,
    peer_cid: u64,
) -> Option<PreSharedKey> {
    if !state_container
        .outgoing_peer_connect_attempts
        .contains_key(&peer_cid)
    {
        return None;
    }
    state_container.get_session_password(peer_cid).cloned()
}

/// Refuses, back through the server, an accept this side will not build a link for. The server
/// relays it on the ticket the accepting (or merged) dialler holds, so that dial ends now: it is
/// answered, and its attempt is no longer read as a dial.
pub(crate) fn refuse_accept<R: Ratchet>(
    sess_ratchet: &R,
    session_cid: u64,
    peer_cid: u64,
    ticket: Ticket,
    error: String,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::warn!(target: "citadel", "Refusing an accept from {peer_cid} on {ticket}: {error}");
    let refusal = PeerSignal::SignalError {
        ticket,
        error,
        peer_connection_type: PeerConnectionType::LocalGroupPeer {
            session_cid,
            peer_cid,
        },
    };
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        sess_ratchet,
        refusal,
        ticket,
        timestamp,
        security_level,
    )?;
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

/// Declines, on its own ticket, a dial this side will not answer otherwise. It is the decline an
/// application sends, so every server and peer version handles it: the server consumes the
/// dial's posting (no later dial is merged with it) and the dialler's dial ends with an answer
/// instead of its timeout.
pub(crate) fn decline_dial<R: Ratchet>(
    sess_ratchet: &R,
    dial: PeerConnectionType,
    ticket: Ticket,
    session_security_settings: SessionSecuritySettings,
    udp_mode: UdpMode,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let decline = PeerSignal::PostConnect {
        peer_conn_type: dial.reverse(),
        ticket_opt: Some(ticket),
        invitee_response: Some(PeerResponse::Decline),
        session_security_settings,
        udp_mode,
        session_password: None,
    };
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        sess_ratchet,
        decline,
        ticket,
        timestamp,
        security_level,
    )?;
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}
