//! Bringing the group registry back when a server node starts, and keeping its durable copy in
//! step with the in-memory one while it runs (see `group_persistence` for what is stored).
//!
//! At start-up no client is connected. Flat groups are restored with their recorded owner, and
//! come back to life by the ordinary reconnect path (`RestoreOwnership` for the owner,
//! `RestoreMembership` for each member). Command-hierarchy groups are dissolved, exactly as they
//! are when their owner's session ends (see `group_retention`).

use crate::error::NetworkError;
use crate::proto::peer::group_persistence::{load_all, store_group};
use crate::proto::peer::group_retention::DissolvedGroup;
use crate::proto::peer::peer_layer::{CitadelNodePeerLayer, CitadelNodePeerLayerInner};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};
use std::collections::HashMap;

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
    /// accepts a connection. Returns the command-hierarchy groups dissolved, to tell their members.
    pub async fn restore_persisted_groups(&self) -> Result<Vec<DissolvedGroup>, NetworkError> {
        let mut this = self.inner.write().await;
        let creators = load_all(&this.persistence_handler).await?;
        let mut dissolved = Vec::new();
        for (creator, persisted) in creators {
            let (flat, hierarchical): (Vec<_>, Vec<_>) =
                persisted.into_iter().partition(|(_, group)| {
                    matches!(group.options.hierarchy, GroupHierarchyMode::Flat)
                });
            for (mgid, group) in hierarchical {
                let key = MessageGroupKey { cid: creator, mgid };
                store_group(&this.persistence_handler, key, None).await?;
                let members = group
                    .members
                    .iter()
                    .copied()
                    .filter(|cid| *cid != group.owner)
                    .collect();
                dissolved.push((key, members));
            }
            if flat.is_empty() {
                continue;
            }
            let groups: HashMap<_, _> = flat
                .into_iter()
                .map(|(mgid, group)| (mgid, group.into_group()))
                .collect();
            log::info!(target: "citadel", "Restored {} group(s) created by {creator}", groups.len());
            let _ = this.message_groups.insert(creator, groups);
        }
        Ok(dissolved)
    }
}
