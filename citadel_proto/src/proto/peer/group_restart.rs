//! Bringing the group registry back when a server node starts, and keeping its durable copy in
//! step with the in-memory one while it runs (see `group_persistence` for what is stored).
//!
//! At start-up no client is connected, so every owner is a departed owner: its flat groups are held
//! for what is left of [`OWNERLESS_GROUP_GRACE`] and restored by the ordinary reconnect path
//! (`RestoreOwnership`, then `RestoreMembership` for each member). Command-hierarchy groups are
//! dissolved, exactly as they are when their owner's session ends (see `group_retention`).

use crate::error::NetworkError;
use crate::proto::peer::group_persistence::{
    load_all, remaining_grace, store_group, store_hold, PersistedGroup,
};
use crate::proto::peer::group_retention::{DissolvedGroup, OWNERLESS_GROUP_GRACE};
use crate::proto::peer::peer_layer::{CitadelNodePeerLayer, CitadelNodePeerLayerInner};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};
use std::collections::HashMap;
use std::time::Duration;

/// A held owner restored at start-up: pass `token` to
/// [`CitadelNodePeerLayer::expire_ownerless_groups`] once `expires_in` has elapsed.
#[derive(Debug, PartialEq, Eq)]
pub struct RestoredHold {
    pub owner: u64,
    pub token: u64,
    pub expires_in: Duration,
}

/// What start-up restored.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoredRegistry {
    /// Command-hierarchy groups, which are not held for a returning owner; tell their members.
    pub dissolved: Vec<DissolvedGroup>,
    pub held: Vec<RestoredHold>,
}

impl<R: Ratchet> CitadelNodePeerLayerInner<R> {
    /// Writes `key`'s current state to the backend, or removes it if the group no longer exists.
    pub(crate) async fn persist_group(&self, key: MessageGroupKey) -> Result<(), NetworkError> {
        let group = self
            .message_groups
            .get(&key.cid)
            .and_then(|groups| groups.get(&key.mgid));
        store_group(&self.persistence_handler, key, group).await
    }

    /// For changes to a group that already exists: the change stands in memory (the group keeps
    /// working), and the failure is logged as what it means, a group a restart would lose or revert.
    pub(crate) async fn persist_group_or_log(&self, key: MessageGroupKey) {
        if let Err(err) = self.persist_group(key).await {
            log::error!(target: "citadel", "{err}: {key:?} will not survive a server restart as it is now");
        }
    }
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Loads the registry from the backend into this (fresh) layer. Called once, before the server
    /// accepts a connection. `now_ns` is ns since the Unix epoch.
    pub async fn restore_persisted_groups(
        &self,
        now_ns: i64,
    ) -> Result<RestoredRegistry, NetworkError> {
        let mut this = self.inner.write().await;
        let owners = load_all(&this.persistence_handler).await?;
        let mut restored = RestoredRegistry::default();
        for (owner, persisted) in owners {
            let (flat, hierarchical): (Vec<_>, Vec<_>) =
                persisted.groups.into_iter().partition(|(_, group)| {
                    matches!(group.options.hierarchy, GroupHierarchyMode::Flat)
                });
            for (mgid, group) in hierarchical {
                let key = MessageGroupKey { cid: owner, mgid };
                store_group(&this.persistence_handler, key, None).await?;
                restored
                    .dissolved
                    .push((key, members_other_than(owner, &group)));
            }
            if flat.is_empty() {
                if persisted.held_since_ns.is_some() {
                    store_hold(&this.persistence_handler, owner, None).await?;
                }
                continue;
            }
            if persisted.held_since_ns.is_none() {
                store_hold(&this.persistence_handler, owner, Some(now_ns)).await?;
            }
            let groups: HashMap<_, _> = flat
                .into_iter()
                .map(|(mgid, group)| (mgid, group.into_group()))
                .collect();
            log::info!(target: "citadel", "Restored {} group(s) owned by {owner}; held for its reconnect", groups.len());
            let _ = this.message_groups.insert(owner, groups);
            this.next_departure_token += 1;
            let token = this.next_departure_token;
            let _ = this.ownerless_groups.insert(owner, token);
            restored.held.push(RestoredHold {
                owner,
                token,
                expires_in: remaining_grace(persisted.held_since_ns, now_ns, OWNERLESS_GROUP_GRACE),
            });
        }
        Ok(restored)
    }
}

fn members_other_than(owner: u64, group: &PersistedGroup) -> Vec<u64> {
    group
        .members
        .iter()
        .copied()
        .filter(|cid| *cid != owner)
        .collect()
}
