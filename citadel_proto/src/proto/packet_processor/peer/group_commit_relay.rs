//! The Commit acknowledgement that orders a join, at the server: relay the owner's Commit, wait on
//! the members it reached (see `group_commit_gate` for the rule), and tell the owner once it has
//! settled.

use super::super::includes::*;
use super::group_broadcast::GroupBroadcast;
use super::group_commit_ack::adjacent_acks;
use crate::constants::GROUP_COMMIT_ACK_SINCE;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::group_commit_gate::Settled;
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;
use std::collections::HashSet;

/// Server: relay a Commit to the group's members. For an owner that takes part, first open the
/// wait on each member that will receive it directly and takes part too, so no acknowledgement
/// can arrive before the wait exists.
#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_commit<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sender: u64,
    key: MessageGroupKey,
    epoch: u64,
    payload: Vec<u8>,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let owner_acks = sender == key.cid && adjacent_acks(&inner_state!(session.state_container));
    let peer_layer = &session.hypernode_peer_layer;
    let manager = &session.session_manager;
    let members: Vec<u64> = peer_layer
        .get_peers_in_message_group(key)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|cid| *cid != sender)
        .collect();
    let mut settled = None;
    if owner_acks {
        let awaiting = manager.connected_at_least(&members, GROUP_COMMIT_ACK_SINCE);
        #[cfg(feature = "localhost-testing")]
        crate::test_hooks::commit_gate_opened(key, epoch, &awaiting);
        settled = peer_layer.open_commit_gate(key, epoch, awaiting).await;
    }
    let commit = GroupBroadcast::Commit {
        key,
        epoch,
        payload,
    };
    let len = members.len();
    // Neither an error nor an undelivered member used to be looked at. A Commit that does not
    // reach the existing members leaves them an epoch behind, unable to decrypt anything sent
    // afterwards -- and the owner has no idea.
    match manager
        .deliver_group_broadcast_signal_to(
            timestamp,
            ticket,
            members.into_iter().zip(std::iter::repeat_n(true, len)),
            true,
            commit,
            security_level,
        )
        .await
    {
        Ok(delivery) => {
            if !delivery.failed.is_empty() {
                log::error!(target: "citadel", "Commit for {key:?} epoch {epoch} was not delivered to {:?}; they will fall behind an epoch and cannot decrypt subsequent messages", delivery.failed);
            }
            let mut undelivered = delivery.mailed;
            undelivered.extend(delivery.failed);
            if owner_acks && !undelivered.is_empty() {
                settled = settled.or(peer_layer
                    .commit_undelivered(key, epoch, &undelivered)
                    .await);
            }
        }
        Err(err) => {
            log::error!(target: "citadel", "Failed to broadcast Commit for {key:?} epoch {epoch}: {err:?}");
        }
    }
    if let Some(settled) = settled {
        manager.notify_commit_settled(settled, ticket, timestamp, security_level);
    }
    Ok(PrimaryProcessorResult::Void)
}

/// Server: `member` has processed the Commit for `epoch`.
pub(super) async fn member_applied_commit<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
    epoch: u64,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if let Some(settled) = session
        .hypernode_peer_layer
        .commit_applied(key, epoch, member)
        .await
    {
        session
            .session_manager
            .notify_commit_settled(settled, ticket, timestamp, security_level);
    }
    Ok(PrimaryProcessorResult::Void)
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// See [`crate::proto::peer::group_commit_gate::CommitGates::open`].
    pub async fn open_commit_gate(
        &self,
        key: MessageGroupKey,
        epoch: u64,
        awaiting: HashSet<u64>,
    ) -> Option<Settled> {
        let mut this = self.inner.write().await;
        // The sessions the Commit is about to be delivered to (and the owner's that made it).
        let owner = this.current_session(key.cid);
        let awaiting = awaiting
            .into_iter()
            .map(|cid| (cid, this.current_session(cid)))
            .collect();
        this.commit_gates.open(key, epoch, owner, awaiting)
    }

    /// See [`crate::proto::peer::group_commit_gate::CommitGates::applied`]. The write lock is fair, so it is taken only after every
    /// relay of a message this member sent earlier has taken its read of the group.
    pub async fn commit_applied(
        &self,
        key: MessageGroupKey,
        epoch: u64,
        member: u64,
    ) -> Option<Settled> {
        self.inner
            .write()
            .await
            .commit_gates
            .applied(key, epoch, member)
    }

    /// See [`crate::proto::peer::group_commit_gate::CommitGates::undelivered`].
    pub async fn commit_undelivered(
        &self,
        key: MessageGroupKey,
        epoch: u64,
        members: &[u64],
    ) -> Option<Settled> {
        self.inner
            .write()
            .await
            .commit_gates
            .undelivered(key, epoch, members)
    }

    /// See [`crate::proto::peer::group_commit_gate::CommitGates::removed`].
    pub async fn commit_gate_members_removed(
        &self,
        key: MessageGroupKey,
        members: &[u64],
    ) -> Option<Settled> {
        self.inner.write().await.commit_gates.removed(key, members)
    }

    /// See [`crate::proto::peer::group_commit_gate::CommitGates::session_ended`]: only the
    /// waits for the session `incarnation` names, so a replaced session's late end neither takes
    /// its replacement out of a wait nor leaves a wait it was in stuck on it.
    pub async fn commit_gate_session_ended(&self, cid: u64, incarnation: Instant) -> Vec<Settled> {
        self.inner
            .write()
            .await
            .commit_gates
            .session_ended(cid, incarnation)
    }
}
