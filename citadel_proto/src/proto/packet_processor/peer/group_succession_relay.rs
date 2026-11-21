//! A member leaving its group, at the server, and ownership passing, at the members (see
//! `peer::group_succession` for the rule).
//!
//! The server decides the successor and records it before it tells anyone, so a Commit or a
//! KeyPackage that follows the news is already routed by the new record. The new owner removes
//! the departed owner's leaf at once and commits from then on; a member still waiting for its
//! Welcome republishes its KeyPackage, which now reaches the new owner.

use super::super::includes::*;
use super::group_broadcast::{
    cgka_joiner_publish_key_package, cgka_owner_refound, forward_signal, GroupBroadcast, JoinMode,
};
use super::group_commit_ack::Crafter;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_succession::Leave;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::proto::{MemberState, MessageGroupKey};

/// Server: `leaver`'s session leaves `key`. `false` when it was not a member.
pub(crate) async fn leave<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    leaver: u64,
    key: MessageGroupKey,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> bool {
    let left = session.hypernode_peer_layer.leave_group(key, leaver).await;
    let was_member = left != Leave::NotAMember;
    tell_members(
        session,
        key,
        leaver,
        left,
        ticket,
        timestamp,
        security_level,
    )
    .await;
    was_member
}

/// Server: `leaver`'s account is gone, so it leaves every group it was in.
pub(crate) async fn leave_every_group<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    leaver: u64,
    timestamp: i64,
    security_level: SecurityLevel,
) {
    for (key, left) in session.hypernode_peer_layer.leave_all_groups(leaver).await {
        tell_members(
            session,
            key,
            leaver,
            left,
            Ticket(0),
            timestamp,
            security_level,
        )
        .await;
    }
}

/// Server: tells the members what `leaver` leaving `key` did. A member offline is mailed it.
async fn tell_members<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    key: MessageGroupKey,
    leaver: u64,
    left: Leave,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) {
    let manager = &session.session_manager;
    let peer_layer = &session.hypernode_peer_layer;
    let mut signals = Vec::with_capacity(2);
    let remaining = match left {
        Leave::NotAMember => return,
        Leave::Closed { remaining } => {
            log::info!(target: "citadel", "{leaver} left {key:?}, which is closed");
            signals.push(GroupBroadcast::Disconnected { key });
            remaining
        }
        Leave::Left { remaining } => {
            if let Some(settled) = peer_layer.commit_gate_members_removed(key, &[leaver]).await {
                manager.notify_commit_settled(settled, ticket, timestamp, security_level);
            }
            signals.push(left_group(key, leaver));
            remaining
        }
        Leave::Transferred {
            owner,
            previous,
            tree,
            remaining,
        } => {
            log::info!(target: "citadel", "Owner {previous} left {key:?}; {owner} owns it now");
            signals.push(left_group(key, leaver));
            signals.push(GroupBroadcast::OwnershipTransferred {
                key,
                owner,
                previous,
                tree,
            });
            remaining
        }
    };
    for signal in signals {
        let len = remaining.len();
        let to = remaining
            .iter()
            .copied()
            .zip(std::iter::repeat_n(true, len));
        if let Err(err) = manager
            .send_group_broadcast_signal_to(timestamp, ticket, to, true, signal, security_level)
            .await
        {
            log::error!(target: "citadel", "Unable to tell the members of {key:?} that {leaver} left: {err}");
        }
    }
}

fn left_group(key: MessageGroupKey, leaver: u64) -> GroupBroadcast {
    GroupBroadcast::MemberStateChanged {
        key,
        state: MemberState::LeftGroup { cids: vec![leaver] },
    }
}

/// What an `OwnershipTransferred` says.
pub(crate) struct Transfer {
    pub key: MessageGroupKey,
    pub owner: u64,
    pub previous: u64,
    pub tree: u64,
}

/// What this member does about a transfer, decided under the state lock.
enum Step {
    /// Nothing beyond telling the application.
    Nothing,
    /// This member is the new owner but holds no usable state: re-found the group.
    Refound,
    /// This member's join was in flight to the departed owner: publish again, to the new one.
    Republish,
}

/// Client: the server reports that `transfer.owner` owns `transfer.key` now.
pub(crate) fn ownership_transferred<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    crafter: &Crafter<'_, R>,
    transfer: Transfer,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let Transfer {
        key,
        owner,
        previous,
        tree,
    } = transfer;
    let session_cid = session
        .session_cid
        .get()
        .ok_or_else(|| error!(ErrorCode::StateImplicatedCidNotLoaded))?;
    let step = {
        let mut state = inner_mut_state!(session.state_container);
        state.record_group_owner(key, Some(owner));
        let held = state.group_cgka.get(&key);
        let pending = held.is_some_and(|cgka| cgka.is_pending_join());
        let usable = held.is_some_and(|cgka| !cgka.is_pending_join() && cgka.is_flat());
        if owner != session_cid {
            if pending {
                Step::Republish
            } else {
                Step::Nothing
            }
        } else if let (true, Some(cgka)) = (usable, state.group_cgka.get_mut(&key)) {
            // The Commit is queued while the state lock is held, so nothing this member seals
            // at the new epoch can reach a member ahead of it.
            if let Some((payload, epoch)) = cgka.take_ownership(previous)? {
                let commit = GroupBroadcast::Commit {
                    key,
                    epoch,
                    payload,
                };
                let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                    crafter.ratchet,
                    &commit,
                    ticket,
                    C2S_IDENTITY_CID,
                    crafter.timestamp,
                    crafter.security_level,
                )?;
                session.send_to_primary_stream(Some(ticket), packet)?;
            }
            Step::Nothing
        } else {
            let _ = state.group_cgka.remove(&key);
            Step::Refound
        }
    };
    let (timestamp, security_level) = (crafter.timestamp, crafter.security_level);
    match step {
        Step::Nothing => {}
        Step::Refound => {
            log::info!(target: "citadel", "{session_cid} owns {key:?} now but holds no state for it; re-founding");
            let _ = cgka_owner_refound(
                session,
                crafter.ratchet,
                key,
                tree,
                ticket,
                timestamp,
                security_level,
            )?;
        }
        Step::Republish => {
            let _ = cgka_joiner_publish_key_package(
                session,
                crafter.ratchet,
                key,
                session_cid,
                ticket,
                timestamp,
                security_level,
                JoinMode::Replace,
            )?;
        }
    }
    forward_signal(
        session,
        ticket,
        Some(key),
        GroupBroadcast::OwnershipTransferred {
            key,
            owner,
            previous,
            tree,
        },
    )
}
