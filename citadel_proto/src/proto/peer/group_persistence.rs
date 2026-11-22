//! The server's message-group registry, kept in the account backend so it outlives the process.
//!
//! The registry (creator → groups, their owners, members, pending invitees) used to live only in
//! [`CitadelNodePeerLayer`]'s memory. A server restart (a Durable Object reset, an eviction, a
//! deploy, a crash) therefore destroyed every group silently: clients reconnected by themselves,
//! the restore protocol (`RestoreOwnership` / `RestoreMembership`) found nothing to restore, and
//! group messages reached nobody.
//!
//! Every change is now written through the backend's byte map (a store every backend already
//! implements: in-memory, filesystem, SQL, Redis, and the host-provided SQL of a Durable Object),
//! and the registry is loaded when a server node starts. The in-memory map stays the authority
//! while the process runs; the backend is its durable copy.
//!
//! Only routing metadata is stored: creator, current owner, group id, type, hierarchy flag and read
//! policy, members and pending invitees. The server never holds CGKA secrets
//! or any other key material, and the rank table of a command hierarchy stays owner-local, so none
//! of that can be written here.
//!
//! Layout: `(owner, 0, "message_groups", <creator cid hex>-<mgid hex>)` → [`PersistedGroup`]. The
//! sub-key is the group's id (`MessageGroupKey`, whose cid is its creator's and stays so after
//! ownership passes); the row is under the account of the owner it was written for, and moves
//! with ownership, so a group outlives its creator's account. A row of an earlier release, keyed
//! by its mgid alone, is refused by name: there is no older format to read.

use crate::error::NetworkError;
use crate::proto::peer::message_group::{MessageGroup, MessageGroupPeer};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey, MessageGroupOptions};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(crate) const GROUPS: &str = "message_groups";
/// Byte-map entries are addressed by `(cid, peer_cid)`; registry rows belong to the owner alone.
const NO_PEER: u64 = 0;

/// What the backend holds for one group. Stored in the layout of
/// [`group_persistence_shape`](super::group_persistence_shape), which reads rows of every age.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    into = "super::group_persistence_shape::StoredGroup",
    from = "super::group_persistence_shape::StoredGroup"
)]
pub struct PersistedGroup {
    pub owner: u64,
    pub options: MessageGroupOptions,
    pub members: Vec<u64>,
    pub pending: Vec<u64>,
    pub tree: u64,
}

impl PersistedGroup {
    pub(crate) fn of(group: &MessageGroup) -> Self {
        let mut options = group.options.clone();
        // The relay is only ever told the flag and read policy; never write a rank table here.
        if let GroupHierarchyMode::CommandHierarchy { ranks, .. } = &mut options.hierarchy {
            *ranks = Default::default();
        }
        let sorted = |peers: &HashMap<u64, MessageGroupPeer>| {
            let mut cids: Vec<u64> = peers.keys().copied().collect();
            cids.sort_unstable();
            cids
        };
        Self {
            owner: group.owner,
            options,
            members: sorted(&group.concurrent_peers),
            pending: sorted(&group.pending_peers),
            tree: group.tree,
        }
    }

    pub(crate) fn into_group(self) -> MessageGroup {
        let peers = |cids: Vec<u64>| {
            cids.into_iter()
                .map(|peer_cid| (peer_cid, MessageGroupPeer { peer_cid }))
                .collect()
        };
        MessageGroup {
            owner: self.owner,
            concurrent_peers: peers(self.members),
            pending_peers: peers(self.pending),
            options: self.options,
            rates: Default::default(),
            tree: self.tree,
            resumed: Default::default(),
        }
    }
}

/// Where one group's row is: the account it is stored under (the group's owner when it was
/// written) and its sub-key, the group's id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub holder: u64,
    pub sub: String,
}

impl Row {
    /// The row `group` is written to: under its owner, keyed by the group's id.
    pub(crate) fn for_group(key: MessageGroupKey, group: &MessageGroup) -> Self {
        Self {
            holder: group.owner,
            sub: format!("{:016x}-{:032x}", key.cid, key.mgid),
        }
    }
}

/// The group a sub-key names. A sub-key that is not a group id (`<cid hex>-<mgid hex>`), such
/// as the mgid-only key of an earlier release, is refused by name: there is no older format.
fn key_of(sub: &str) -> Result<MessageGroupKey, NetworkError> {
    let parse_err = |err| persistence_error(&format!("parse group id {sub:?}"), err);
    let (cid, mgid) = sub.split_once('-').ok_or_else(|| {
        persistence_error(
            "read a group row",
            format!("{sub:?} is a row of an earlier release, not a group id; it is not read"),
        )
    })?;
    Ok(MessageGroupKey {
        cid: u64::from_str_radix(cid, 16).map_err(parse_err)?,
        mgid: u128::from_str_radix(mgid, 16).map_err(parse_err)?,
    })
}

fn persistence_error(what: &str, err: impl std::fmt::Display) -> NetworkError {
    NetworkError::msg(format!("group registry: unable to {what}: {err}"))
}

/// Writes `group` to `row`.
pub(crate) async fn store_row<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    row: &Row,
    group: &MessageGroup,
) -> Result<(), NetworkError> {
    let bytes = PersistedGroup::of(group)
        .serialize_to_vector()
        .map_err(|err| persistence_error("encode a group", err))?;
    let _ = pers
        .store_byte_map_value(row.holder, NO_PEER, GROUPS, &row.sub, bytes)
        .await
        .map_err(|err| persistence_error("store a group", err))?;
    Ok(())
}

/// Removes `row`.
pub(crate) async fn remove_row<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    row: &Row,
) -> Result<(), NetworkError> {
    let _ = pers
        .remove_byte_map_value(row.holder, NO_PEER, GROUPS, &row.sub)
        .await
        .map_err(|err| persistence_error("remove a group", err))?;
    Ok(())
}

/// One group as the backend holds it, and where.
pub(crate) type PersistedRow = (MessageGroupKey, Row, PersistedGroup);

/// Reads every account's group rows. A row that does not decode is an error, not a skipped group:
/// a group dropped here would be the same silent loss this module exists to prevent.
pub(crate) async fn load_all<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
) -> Result<Vec<PersistedRow>, NetworkError> {
    let accounts = pers
        .get_clients_metadata(None)
        .await
        .map_err(|err| persistence_error("list accounts", err))?;
    let mut rows = Vec::new();
    for account in accounts {
        let holder = account.cid;
        let held = pers
            .get_byte_map_values_by_key(holder, NO_PEER, GROUPS)
            .await
            .map_err(|err| persistence_error("read groups", err))?;
        for (sub, bytes) in held {
            let key = key_of(&sub)?;
            let group = PersistedGroup::deserialize_from_vector(&bytes)
                .map_err(|err| persistence_error(&format!("decode group {sub}"), err))?;
            rows.push((key, Row { holder, sub }, group));
        }
    }
    Ok(rows)
}

#[cfg(test)]
#[path = "group_persistence_tests.rs"]
mod tests;
