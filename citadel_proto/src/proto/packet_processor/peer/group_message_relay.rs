//! The server's relay of one group message: admitted against the group's limits, then fanned
//! out to the members (mailed to the offline ones unless the group is ephemeral; see
//! `session_manager::broadcast_signal_to_group`), with the sender told the result.

use super::group_broadcast::GroupBroadcast;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use citadel_types::proto::MessageGroupKey;

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
            return GroupBroadcast::MessageRefused { key, refusal };
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
