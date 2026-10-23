//! The server's relay of one group message: admitted against the group's limits, then fanned
//! out to the members (mailed to the offline ones unless the group is ephemeral; see
//! `session_manager::broadcast_signal_to_group`), with the sender told the result.

use super::group_broadcast::GroupBroadcast;
use crate::constants::{protocol_version_at_least, GROUP_RELAY_OPTIONS_SINCE};
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use citadel_types::proto::{GroupMessageRefusal, MessageGroupKey};

/// One group message, as the server received it from its sender's session.
pub(crate) struct InboundGroupMessage {
    pub session_cid: u64,
    pub sender: u64,
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
        sender,
        key,
        message,
        ticket,
        timestamp,
        security_level,
    } = inbound;
    // Rate is charged to the session that sent it, never to the `sender` it claims.
    let admitted = session
        .hypernode_peer_layer
        .admit_group_message(key, session_cid, message.len(), Instant::now())
        .await;
    let targets = match admitted {
        Ok(targets) => targets,
        Err(refusal) => {
            log::warn!(target: "citadel", "Refusing a group message from {session_cid} to {key:?}: {refusal}");
            let sender_version = inner_state!(session.state_container).adjacent_protocol_version;
            return refusal_reply(key, refusal, sender_version);
        }
    };
    let success = session
        .session_manager
        .broadcast_signal_to_targets(
            session_cid,
            timestamp,
            ticket,
            targets,
            GroupBroadcast::Message {
                sender,
                key,
                message,
            },
            security_level,
        )
        .await
        .unwrap_or(false);
    GroupBroadcast::MessageResponse { key, success }
}

/// What a sender at `sender_version` is told of a refused message: why, if it can read the
/// refusal, otherwise the failure it has always been sent.
fn refusal_reply(
    key: MessageGroupKey,
    refusal: GroupMessageRefusal,
    sender_version: Option<u32>,
) -> GroupBroadcast {
    if protocol_version_at_least(sender_version, GROUP_RELAY_OPTIONS_SINCE) {
        GroupBroadcast::MessageRefused { key, refusal }
    } else {
        GroupBroadcast::MessageResponse {
            key,
            success: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROTOCOL_VERSION;
    use embedded_semver::Semver;

    const KEY: MessageGroupKey = MessageGroupKey { cid: 1, mgid: 2 };
    const REFUSAL: GroupMessageRefusal = GroupMessageRefusal::RateLimited { max_per_second: 4 };

    #[test]
    fn a_sender_that_reads_refusals_is_told_why() {
        match refusal_reply(KEY, REFUSAL, Some(*PROTOCOL_VERSION)) {
            GroupBroadcast::MessageRefused { key, refusal } => {
                assert_eq!((key, refusal), (KEY, REFUSAL))
            }
            other => panic!("not a refusal: {other:?}"),
        }
    }

    #[test]
    fn an_older_sender_is_told_only_that_the_message_failed() {
        let older = Some(Semver::new(0, 12, 1).to_u32().unwrap());
        for version in [older, None] {
            assert!(matches!(
                refusal_reply(KEY, REFUSAL, version),
                GroupBroadcast::MessageResponse { success: false, .. }
            ));
        }
    }
}
