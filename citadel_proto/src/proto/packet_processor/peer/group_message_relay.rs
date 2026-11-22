//! The server's relay of one group message: admitted against the group's limits, then fanned
//! out to the members (mailed to the offline ones unless the group is ephemeral; see
//! `session_manager::broadcast_signal_to_group`), with the sender told the result.

use super::group_broadcast::GroupBroadcast;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::session_manager::GroupFanOut;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use citadel_types::proto::{GroupDelivery, MessageGroupKey, NotDelivered, NotRelayed};

/// One group message, as the server received it from its sender's session.
pub(crate) struct InboundGroupMessage {
    /// The sending session: the sender every member is told of.
    pub session_cid: u64,
    pub key: MessageGroupKey,
    pub message: SecBuffer,
    pub ticket: Ticket,
    pub timestamp: i64,
    pub security_level: SecurityLevel,
}

/// Server: relays `inbound` and returns the answer for its sender.
pub(crate) async fn relay<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    inbound: InboundGroupMessage,
) -> GroupBroadcast {
    let InboundGroupMessage {
        session_cid,
        key,
        message,
        ticket,
        timestamp,
        security_level,
    } = inbound;
    #[cfg(feature = "localhost-testing")]
    crate::test_hooks::before_group_relay(session_cid).await;
    // The sender is the session that sent it, never the `sender` the message claims: that cid is
    // both what the rate is charged to and what every member is told.
    let admitted = session
        .hypernode_peer_layer
        .admit_group_message(key, session_cid, message.len(), Instant::now())
        .await;
    let targets = match admitted {
        Ok(targets) => targets,
        Err(refusal) => {
            log::warn!(target: "citadel", "Refusing a group message from {session_cid} to {key:?}: {refusal}");
            return GroupBroadcast::MessageRefused { key, refusal };
        }
    };
    let Some(targets) = targets else {
        return GroupBroadcast::MessageResponse {
            key,
            delivery: GroupDelivery::NotRelayed(NotRelayed::UnknownGroup),
        };
    };
    let others = targets
        .members
        .iter()
        .copied()
        .filter(|member| *member != session_cid)
        .map(|member| (member, true));
    let fan_out = session
        .session_manager
        .deliver_group_broadcast_signal_to(
            timestamp,
            ticket,
            others,
            targets.mail_if_offline,
            GroupBroadcast::Message {
                sender: session_cid,
                key,
                message,
            },
            security_level,
        )
        .await;
    let delivery = match fan_out {
        Ok(fan_out) => delivery_of(fan_out),
        Err(err) => {
            log::error!(target: "citadel", "Unable to relay a group message from {session_cid} to {key:?}: {err}");
            GroupDelivery::NotRelayed(NotRelayed::UnknownGroup)
        }
    };
    #[cfg(feature = "localhost-testing")]
    crate::test_hooks::group_message_relayed(key, session_cid, delivery.is_complete());
    GroupBroadcast::MessageResponse { key, delivery }
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
