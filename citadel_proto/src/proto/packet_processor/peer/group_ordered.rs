//! A member's side of a group's order, once a broadcast has arrived in order (`group_arrivals`):
//! a message reaches the application with its position, and so does a positioned event of a
//! replay group; the answers to replay requests are handed on.

use super::group_broadcast::{forward_signal, GroupBroadcast};
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::group_channel::GroupBroadcastPayload;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupPosition, MessageGroupKey};

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

/// What the application receives for `event`: positioned when it came positioned (a membership
/// or ownership change, or replay turned on, in a replay group).
pub(super) fn event_at(
    key: MessageGroupKey,
    position: Option<GroupPosition>,
    event: GroupBroadcast,
) -> GroupBroadcast {
    match position {
        Some(position) => opened(key, position, event),
        None => event,
    }
}

/// Member: a replay answer (`ReplayRefused`, `Trimmed`, `OrderBroken`) for the application; a
/// server ignores one.
pub(super) fn replay_answer<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ticket: Ticket,
    answer: GroupBroadcast,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let key = match &answer {
        GroupBroadcast::ReplayRefused { key, .. }
        | GroupBroadcast::Trimmed { key, .. }
        | GroupBroadcast::OrderBroken { key, .. } => *key,
        _ => return Ok(PrimaryProcessorResult::Void),
    };
    if session.is_server {
        log::warn!(target: "citadel", "Ignoring a replay answer for {key:?}: only a member takes one");
        return Ok(PrimaryProcessorResult::Void);
    }
    forward_signal(session, ticket, Some(key), answer)
}
