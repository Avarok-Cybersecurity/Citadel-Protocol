//! Bringing the group registry back when a server node starts, and keeping its durable copy in
//! step with the in-memory one while it runs (see `group_persistence` for what is stored).
//!
//! At start-up no client is connected. Flat groups are restored with their recorded owner, and
//! come back to life by the ordinary reconnect path (`RestoreOwnership` for the owner,
//! `RestoreMembership` for each member). Command-hierarchy groups are dissolved, exactly as they
//! are when their owner's session ends (see `group_retention`).

use crate::error::NetworkError;
use crate::proto::peer::group_persistence::{load_all, remove_row, store_row, PersistedRow, Row};
use crate::proto::peer::group_retention::DissolvedGroup;
use crate::proto::peer::peer_layer::{CitadelNodePeerLayer, CitadelNodePeerLayerInner};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};
use std::collections::HashMap;

impl<R: Ratchet> CitadelNodePeerLayerInner<R> {
    /// Writes `key`'s current state to the backend, or removes it if the group no longer exists.
    /// A row whose owner changed is written under the new owner before the old one is removed, so
    /// a failure between the two leaves a duplicate (resolved at load), never no row.
    pub(crate) async fn persist_group(&mut self, key: MessageGroupKey) -> Result<(), NetworkError> {
        let group = self
            .message_groups
            .get(&key.cid)
            .and_then(|groups| groups.get(&key.mgid));
        let previous = self.group_rows.get(&key).cloned();
        let pers = &self.persistence_handler;
        match group {
            Some(group) => {
                let row = Row::for_group(key, group);
                store_row(pers, &row, group).await?;
                if let Some(previous) = previous.filter(|previous| *previous != row) {
                    remove_row(pers, &previous).await?;
                }
                let _ = self.group_rows.insert(key, row);
            }
            None => {
                if let Some(previous) = previous {
                    remove_row(pers, &previous).await?;
                }
                let _ = self.group_rows.remove(&key);
            }
        }
        Ok(())
    }

    /// For changes to a group that already exists: the change stands in memory (the group keeps
    /// working), and the failure is logged as what it means, a group a restart would lose or revert.
    pub(crate) async fn persist_group_or_log(&mut self, key: MessageGroupKey) {
        if let Err(err) = self.persist_group(key).await {
            log::error!(target: "citadel", "{err}: {key:?} will not survive a server restart as it is now");
        }
    }
}

/// Keeps one row per group, preferring the one under the group's recorded owner, and removes the
/// rest: a second row is left only by a move to a new owner that did not finish.
async fn one_row_per_group<R: Ratchet>(
    this: &CitadelNodePeerLayerInner<R>,
    rows: Vec<PersistedRow>,
) -> Result<Vec<PersistedRow>, NetworkError> {
    let mut kept: HashMap<MessageGroupKey, PersistedRow> = HashMap::with_capacity(rows.len());
    for candidate in rows {
        let key = candidate.0;
        let stale = match kept.remove(&key) {
            None => None,
            Some(held) if held.1.holder == held.2.owner => {
                let stale = candidate.1.clone();
                let _ = kept.insert(key, held);
                Some(stale)
            }
            Some(held) => Some(held.1),
        };
        if let Some(stale) = stale {
            remove_row(&this.persistence_handler, &stale).await?;
        }
        let _ = kept.entry(key).or_insert(candidate);
    }
    Ok(kept.into_values().collect())
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Loads the registry from the backend into this (fresh) layer. Called once, before the server
    /// accepts a connection. Returns the command-hierarchy groups dissolved, to tell their members.
    pub async fn restore_persisted_groups(&self) -> Result<Vec<DissolvedGroup>, NetworkError> {
        let mut this = self.inner.write().await;
        let mut dissolved = Vec::new();
        let mut restored = 0usize;
        for (key, row, group) in
            one_row_per_group(&this, load_all(&this.persistence_handler).await?).await?
        {
            if !matches!(group.options.hierarchy, GroupHierarchyMode::Flat) {
                remove_row(&this.persistence_handler, &row).await?;
                let _ = this.group_rows.remove(&key);
                let members = group
                    .members
                    .iter()
                    .copied()
                    .filter(|cid| *cid != group.owner)
                    .collect();
                dissolved.push((key, members));
                continue;
            }
            let _ = this.group_rows.insert(key, row);
            let _ = this
                .message_groups
                .entry(key.cid)
                .or_default()
                .insert(key.mgid, group.into_group());
            restored += 1;
        }
        log::info!(target: "citadel", "Restored {restored} group(s)");
        Ok(dissolved)
    }
}

#[cfg(test)]
#[path = "group_restart_tests.rs"]
mod tests;
