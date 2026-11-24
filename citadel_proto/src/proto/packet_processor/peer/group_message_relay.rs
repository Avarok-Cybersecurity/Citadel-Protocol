//! The server's relay of one group message: admitted against the group's limits, positioned in
//! the group's order, then fanned out to the members (mailed to the offline ones unless the group
//! is ephemeral; see `session_manager::broadcast_signal_to_group`), with the sender told the
//! result and the position.
//!
//! The sender's answer is written to its stream before the group's order lock is released, so
//! the sender learns its message's position before it receives any broadcast positioned after it.

use super::group_broadcast::GroupBroadcast;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::group_position::Positioned;
use crate::proto::peer::group_sequencer::GroupOrderBook;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::session_manager::GroupFanOut;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use citadel_types::proto::{
    GroupDelivery, GroupMessageId, GroupPosition, MessageGroupKey, NotDelivered, NotRelayed,
};

/// One group message, as the server received it from its sender's session.
pub(crate) struct InboundGroupMessage {
    /// The sending session: the sender every member is told of.
    pub session_cid: u64,
    pub key: MessageGroupKey,
    pub id: GroupMessageId,
    pub message: SecBuffer,
    pub ticket: Ticket,
    pub timestamp: i64,
    pub security_level: SecurityLevel,
}

/// Server: relays `inbound` and answers its sender.
pub(crate) async fn relay<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    inbound: InboundGroupMessage,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (ticket, timestamp, security_level) =
        (inbound.ticket, inbound.timestamp, inbound.security_level);
    let answer = |signal: &GroupBroadcast| {
        packet_crafter::peer_cmd::craft_group_message_packet(
            sess_ratchet,
            signal,
            ticket,
            C2S_IDENTITY_CID,
            timestamp,
            security_level,
        )
    };
    match fan_out(session, inbound).await {
        Relay::Refused(refusal) => Ok(PrimaryProcessorResult::ReplyToSender(answer(&refusal)?)),
        Relay::Answered(response, _book) => {
            session.send_to_primary_stream(Some(ticket), answer(&response)?)?;
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

/// What became of a message: refused before it was positioned, or answered with the group's
/// order lock still held (the guard), to be written to the sender before it is released.
enum Relay {
    Refused(GroupBroadcast),
    Answered(GroupBroadcast, Option<citadel_io::tokio::sync::OwnedMutexGuard<GroupOrderBook>>),
}

async fn fan_out<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    inbound: InboundGroupMessage,
) -> Relay {
    let InboundGroupMessage {
        session_cid,
        key,
        id,
        message,
        ticket,
        timestamp,
        security_level,
    } = inbound;
    #[cfg(feature = "localhost-testing")]
    crate::test_hooks::before_group_relay(session_cid).await;
    let response = |position: Option<GroupPosition>, delivery| GroupBroadcast::MessageResponse {
        key,
        id,
        position,
        delivery,
    };
    // The sender is the session that sent it, never the `sender` the message claims: that cid is
    // both what the rate is charged to and what every member is told.
    let peer_layer = &session.hypernode_peer_layer;
    let admitted = peer_layer
        .admit_group_message(key, session_cid, message.len(), Instant::now())
        .await;
    let targets = match admitted {
        Ok(Some(targets)) => targets,
        Ok(None) => {
            let unknown = GroupDelivery::NotRelayed(NotRelayed::UnknownGroup);
            return Relay::Answered(response(None, unknown), None);
        }
        Err(refusal) => {
            log::warn!(target: "citadel", "Refusing a group message from {session_cid} to {key:?}: {refusal}");
            return Relay::Refused(GroupBroadcast::MessageRefused { key, refusal });
        }
    };
    let mut book = peer_layer.group_order.clone().lock_owned().await;
    let signal = GroupBroadcast::Message {
        sender: session_cid,
        key,
        id,
        message,
    };
    let now_ns = session.time_tracker.get_global_time_ns();
    let positioned = peer_layer
        .position_group_broadcast(&mut book, key, signal, now_ns)
        .await;
    let (frame, position) = match positioned {
        Ok(Positioned::New { frame, position }) => (frame, position),
        Ok(Positioned::Retry { position }) => {
            let again = GroupDelivery::NotRelayed(NotRelayed::AlreadyRelayed);
            return Relay::Answered(response(Some(position), again), Some(book));
        }
        Err(err) => {
            log::error!(target: "citadel", "Unable to position a group message from {session_cid} to {key:?}: {err}");
            let unstored = GroupDelivery::NotRelayed(NotRelayed::NotPositioned);
            return Relay::Answered(response(None, unstored), Some(book));
        }
    };
    let others = targets
        .members
        .iter()
        .copied()
        .filter(|member| *member != session_cid)
        .map(|member| (member, true));
    let fan_out = session
        .session_manager
        .deliver_positioned(
            Some((key, position)),
            timestamp,
            ticket,
            others,
            targets.mail_if_offline,
            frame,
            security_level,
        )
        .await;
    let delivery = match fan_out {
        Ok(fan_out) => delivery_of(fan_out),
        Err(err) => {
            // The position stands: members reached before the failure have the message.
            log::error!(target: "citadel", "Unable to relay a group message from {session_cid} to {key:?}: {err}");
            GroupDelivery::NotRelayed(NotRelayed::UnknownGroup)
        }
    };
    #[cfg(feature = "localhost-testing")]
    crate::test_hooks::group_message_relayed(key, session_cid, delivery.is_complete());
    Relay::Answered(response(Some(position), delivery), Some(book))
}

/// The sender's account of a fan-out, member by member.
fn delivery_of(fan_out: GroupFanOut) -> GroupDelivery {
    let not_delivered = fan_out
        .offline
        .into_iter()
        .map(|member| (member, NotDelivered::Offline))
        .chain(
            fan_out
                .backlog_full
                .into_iter()
                .map(|member| (member, NotDelivered::BacklogFull)),
        )
        .chain(
            fan_out
                .failed
                .into_iter()
                .map(|member| (member, NotDelivered::Unreachable)),
        )
        .collect();
    GroupDelivery::Relayed {
        delivered: fan_out.direct,
        stored: fan_out.mailed,
        not_delivered,
    }
}
