//! A member's side of a group's order: a positioned broadcast ([`GroupBroadcast::Ordered`]) is
//! taken apart before it is processed, handed on at most once per position (`group_delivered`),
//! and a message reaches the application with its position.
//!
//! Also the answers to the replay requests, which this release refuses (`NotApplicable`): a
//! group keeps no log yet.

use super::group_broadcast::{forward_signal, GroupBroadcast};
use super::group_restore::Reply;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::group_channel::GroupBroadcastPayload;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupPosition, GroupReplayRefusal, MessageGroupKey};

/// A broadcast to process, and its position when it came positioned. `None` when there is
/// nothing to process: a position this node delivered already, or one sent to the wrong side.
pub(super) fn unwrap_ordered<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    session_cid: u64,
    signal: GroupBroadcast,
) -> Option<(GroupBroadcast, Option<GroupPosition>)> {
    let GroupBroadcast::Ordered {
        key,
        position,
        frame,
    } = signal
    else {
        return Some((signal, None));
    };
    if session.is_server || matches!(*frame, GroupBroadcast::Ordered { .. }) {
        log::warn!(target: "citadel", "Ignoring a positioned broadcast for {key:?}: only a server positions, and only once");
        return None;
    }
    let first_time = session
        .hypernode_peer_layer
        .group_delivered
        .lock()
        .first_time(session_cid, key, position.seq);
    if !first_time {
        log::trace!(target: "citadel", "Dropping position {} of {key:?}: delivered already", position.seq);
        return None;
    }
    Some((*frame, Some(position)))
}

/// What the application receives for an opened message.
pub(super) fn opened(
    key: MessageGroupKey,
    position: GroupPosition,
    message: GroupBroadcast,
) -> GroupBroadcast {
    GroupBroadcast::Ordered {
        key,
        position,
        frame: Box::new(message),
    }
}

/// The application's view of a broadcast: an opened message with its position, or an event.
pub(super) fn to_payload(broadcast: GroupBroadcast) -> GroupBroadcastPayload {
    match broadcast {
        GroupBroadcast::Ordered {
            key,
            position,
            frame,
        } => match *frame {
            GroupBroadcast::Message {
                sender,
                id,
                message,
                ..
            } => GroupBroadcastPayload::Message {
                payload: message,
                sender,
                id,
                position,
            },
            frame => GroupBroadcastPayload::Event {
                payload: GroupBroadcast::Ordered {
                    key,
                    position,
                    frame: Box::new(frame),
                },
            },
        },
        evt => GroupBroadcastPayload::Event { payload: evt },
    }
}

/// [`to_payload`] undone, for a payload the channel no longer takes.
pub(super) fn from_payload(key: MessageGroupKey, payload: GroupBroadcastPayload) -> GroupBroadcast {
    match payload {
        GroupBroadcastPayload::Event { payload } => payload,
        GroupBroadcastPayload::Message {
            payload,
            sender,
            id,
            position,
        } => opened(
            key,
            position,
            GroupBroadcast::Message {
                sender,
                key,
                id,
                message: payload,
            },
        ),
    }
}

/// Server: a replay request (`EnableReplay`, `FetchRange`) for `key`, refused.
pub(super) fn refuse_replay<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if !session.is_server {
        log::warn!(target: "citadel", "Ignoring a replay request for {key:?}: only a server answers one");
        return Ok(PrimaryProcessorResult::Void);
    }
    reply.send(GroupBroadcast::ReplayRefused {
        key,
        refusal: GroupReplayRefusal::NotApplicable,
    })
}

/// Member: a replay answer (`ReplayRefused`, `Trimmed`) for the application; a server ignores
/// one, and nothing sends `Range` or `OrderBroken` to this release.
pub(super) fn replay_answer<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ticket: Ticket,
    answer: GroupBroadcast,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (key, for_application) = match &answer {
        GroupBroadcast::ReplayRefused { key, .. } | GroupBroadcast::Trimmed { key, .. } => {
            (*key, true)
        }
        GroupBroadcast::ReplayEnabled { key, .. }
        | GroupBroadcast::Range { key, .. }
        | GroupBroadcast::OrderBroken { key, .. } => (*key, false),
        _ => return Ok(PrimaryProcessorResult::Void),
    };
    if session.is_server || !for_application {
        log::warn!(target: "citadel", "Ignoring a replay answer for {key:?} this node does not take");
        return Ok(PrimaryProcessorResult::Void);
    }
    forward_signal(session, ticket, Some(key), answer)
}
