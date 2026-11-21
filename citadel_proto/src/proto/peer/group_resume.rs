//! A member's return to a group, at the server.
//!
//! A member that kept its group state answers the server's `RestoreMembership` prompt with
//! `ResumeMembership`, and its owner with `ResumeOwnership`. The server then replays, oldest first,
//! what it held for the member while it was away (see `group_mail`), and only after that sends it
//! the group's broadcasts live. Both happen under the peer layer's group mail lock, which every
//! group fan-out also holds, so a broadcast is either in the replay or sent after it.
//!
//! A member that holds no state for the group's current tree publishes a KeyPackage instead, as
//! a joiner does; it is back once its Welcome is relayed.

use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;
use std::collections::HashSet;

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// The generation of `key`'s ratchet tree, if the group exists here.
    pub async fn group_tree(&self, key: MessageGroupKey) -> Option<u64> {
        let this = self.inner.read().await;
        Some(this.message_groups.get(&key.cid)?.get(&key.mgid)?.tree)
    }

    /// Marks `member`'s current session back in `key`. `false` when it is not a member.
    pub async fn mark_resumed(&self, key: MessageGroupKey, member: u64) -> bool {
        let mut this = self.inner.write().await;
        let Some(group) = this
            .message_groups
            .get_mut(&key.cid)
            .and_then(|groups| groups.get_mut(&key.mgid))
        else {
            return false;
        };
        if !group.concurrent_peers.contains_key(&member) {
            return false;
        }
        let _ = group.resumed.insert(member);
        true
    }

    /// The members of `key` whose current session is back in the group.
    pub async fn resumed_members(&self, key: MessageGroupKey) -> HashSet<u64> {
        let this = self.inner.read().await;
        this.message_groups
            .get(&key.cid)
            .and_then(|groups| groups.get(&key.mgid))
            .map(|group| group.resumed.clone())
            .unwrap_or_default()
    }

    /// The owner founded `key`'s tree afresh: no member is in it until it rejoins. Returns the
    /// new tree generation and the members to prompt, once the group is persisted with it.
    pub async fn refound_tree(&self, key: MessageGroupKey) -> Option<(u64, Vec<u64>)> {
        let mut this = self.inner.write().await;
        let group = this.message_groups.get_mut(&key.cid)?.get_mut(&key.mgid)?;
        group.tree += 1;
        group.resumed.clear();
        let _ = group.resumed.insert(key.cid);
        let tree = group.tree;
        let members = group
            .concurrent_peers
            .keys()
            .copied()
            .filter(|cid| *cid != key.cid)
            .collect();
        this.persist_group_or_log(key).await;
        Some((tree, members))
    }
}
