//! The server's message-group registry, kept in the account backend so it outlives the process.
//!
//! The registry (owner → groups, members, pending invitees, retention holds) used to live only in
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
//! Only routing metadata is stored: owner, group id, type, hierarchy flag and read policy, members,
//! pending invitees, and when the owner's retention hold began. The server never holds CGKA secrets
//! or any other key material, and the rank table of a command hierarchy stays owner-local, so none
//! of that can be written here.
//!
//! Layout: `(owner, 0, "message_groups", <mgid hex>)` → [`PersistedGroup`], and
//! `(owner, 0, "message_group_hold", "since_ns")` → the hold's start, in ns since the Unix epoch.

use crate::error::NetworkError;
use crate::proto::peer::message_group::{MessageGroup, MessageGroupPeer};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey, MessageGroupOptions};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const GROUPS: &str = "message_groups";
const HOLD: &str = "message_group_hold";
const HOLD_SINCE: &str = "since_ns";
/// Byte-map entries are addressed by `(cid, peer_cid)`; registry rows belong to the owner alone.
const NO_PEER: u64 = 0;

/// What the backend holds for one group.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedGroup {
    pub options: MessageGroupOptions,
    pub members: Vec<u64>,
    pub pending: Vec<u64>,
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
            options,
            members: sorted(&group.concurrent_peers),
            pending: sorted(&group.pending_peers),
        }
    }

    pub(crate) fn into_group(self) -> MessageGroup {
        let peers = |cids: Vec<u64>| {
            cids.into_iter()
                .map(|peer_cid| (peer_cid, MessageGroupPeer { peer_cid }))
                .collect()
        };
        MessageGroup {
            concurrent_peers: peers(self.members),
            pending_peers: peers(self.pending),
            options: self.options,
        }
    }
}

fn sub_key(mgid: u128) -> String {
    format!("{mgid:032x}")
}

fn persistence_error(what: &str, err: impl std::fmt::Display) -> NetworkError {
    NetworkError::msg(format!("group registry: unable to {what}: {err}"))
}

/// Writes the group's current state, or removes its row when `group` is `None`.
pub(crate) async fn store_group<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    key: MessageGroupKey,
    group: Option<&MessageGroup>,
) -> Result<(), NetworkError> {
    let sub = sub_key(key.mgid);
    match group {
        Some(group) => {
            let bytes = PersistedGroup::of(group)
                .serialize_to_vector()
                .map_err(|err| persistence_error("encode a group", err))?;
            pers.store_byte_map_value(key.cid, NO_PEER, GROUPS, &sub, bytes)
                .await
                .map_err(|err| persistence_error("store a group", err))?;
        }
        None => {
            pers.remove_byte_map_value(key.cid, NO_PEER, GROUPS, &sub)
                .await
                .map_err(|err| persistence_error("remove a group", err))?;
        }
    }
    Ok(())
}

/// Records that `owner`'s groups are being held since `since_ns`, or clears the hold.
pub(crate) async fn store_hold<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    owner: u64,
    since_ns: Option<i64>,
) -> Result<(), NetworkError> {
    match since_ns {
        Some(since) => pers
            .store_byte_map_value(
                owner,
                NO_PEER,
                HOLD,
                HOLD_SINCE,
                since.to_be_bytes().to_vec(),
            )
            .await
            .map(|_| ()),
        None => pers
            .remove_byte_map_value(owner, NO_PEER, HOLD, HOLD_SINCE)
            .await
            .map(|_| ()),
    }
    .map_err(|err| persistence_error("store a retention hold", err))
}

/// One owner's registry as the backend holds it.
#[derive(Debug, Default)]
pub struct PersistedOwner {
    pub groups: HashMap<u128, PersistedGroup>,
    pub held_since_ns: Option<i64>,
}

/// Reads every owner's registry. A row that does not decode is an error, not a skipped group: a
/// group dropped here would be the same silent loss this module exists to prevent.
pub(crate) async fn load_all<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
) -> Result<HashMap<u64, PersistedOwner>, NetworkError> {
    let accounts = pers
        .get_clients_metadata(None)
        .await
        .map_err(|err| persistence_error("list accounts", err))?;
    let mut owners = HashMap::new();
    for account in accounts {
        let owner = account.cid;
        let rows = pers
            .get_byte_map_values_by_key(owner, NO_PEER, GROUPS)
            .await
            .map_err(|err| persistence_error("read groups", err))?;
        if rows.is_empty() {
            continue;
        }
        let mut groups = HashMap::with_capacity(rows.len());
        for (sub, bytes) in rows {
            let mgid = u128::from_str_radix(&sub, 16)
                .map_err(|err| persistence_error(&format!("parse group id {sub:?}"), err))?;
            let group = PersistedGroup::deserialize_from_vector(&bytes)
                .map_err(|err| persistence_error(&format!("decode group {sub}"), err))?;
            let _ = groups.insert(mgid, group);
        }
        let held_since_ns = pers
            .get_byte_map_value(owner, NO_PEER, HOLD, HOLD_SINCE)
            .await
            .map_err(|err| persistence_error("read a retention hold", err))?
            .map(|bytes| {
                <[u8; 8]>::try_from(bytes.as_slice())
                    .map(i64::from_be_bytes)
                    .map_err(|_| persistence_error("decode a retention hold", "not 8 bytes"))
            })
            .transpose()?;
        let _ = owners.insert(
            owner,
            PersistedOwner {
                groups,
                held_since_ns,
            },
        );
    }
    Ok(owners)
}

/// How much of the grace period an owner has left at start-up. At start-up no owner is connected,
/// so every owner is departed: one whose hold began before the restart keeps the remainder of it;
/// one that was connected when the server went down starts a full grace period now.
pub fn remaining_grace(held_since_ns: Option<i64>, now_ns: i64, grace: Duration) -> Duration {
    let Some(since) = held_since_ns else {
        return grace;
    };
    let elapsed = Duration::from_nanos(now_ns.saturating_sub(since).max(0) as u64);
    grace.saturating_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::{GroupType, ReadPolicy};

    fn group(hierarchy: GroupHierarchyMode) -> MessageGroup {
        PersistedGroup {
            options: MessageGroupOptions {
                group_type: GroupType::Private,
                id: 7,
                hierarchy,
            },
            members: vec![1, 2],
            pending: vec![3],
        }
        .into_group()
    }

    #[test]
    fn a_group_round_trips_through_its_persisted_form() {
        let original = group(GroupHierarchyMode::Flat);
        let bytes = PersistedGroup::of(&original).serialize_to_vector().unwrap();
        let back = PersistedGroup::deserialize_from_vector(&bytes).unwrap();
        assert_eq!(back.options.id, 7);
        assert_eq!(back.options.group_type, GroupType::Private);
        assert_eq!(back.options.hierarchy, GroupHierarchyMode::Flat);
        assert_eq!(back.members, vec![1, 2]);
        assert_eq!(back.pending, vec![3]);
    }

    #[test]
    fn a_hierarchy_keeps_its_flag_and_read_policy_but_never_a_rank_table() {
        let mut ranks = HashMap::new();
        let _ = ranks.insert(2, citadel_types::proto::CommandPath::parse("/HQ/Bn1"));
        let persisted = PersistedGroup::of(&group(GroupHierarchyMode::CommandHierarchy {
            read_policy: ReadPolicy::SuperiorOnly,
            ranks,
        }));
        assert_eq!(
            persisted.options.hierarchy,
            GroupHierarchyMode::CommandHierarchy {
                read_policy: ReadPolicy::SuperiorOnly,
                ranks: Default::default(),
            }
        );
    }

    #[test]
    fn a_hold_keeps_only_what_is_left_of_its_grace() {
        let grace = Duration::from_secs(900);
        let sec = 1_000_000_000i64;
        assert_eq!(remaining_grace(None, 50 * sec, grace), grace);
        assert_eq!(
            remaining_grace(Some(0), 60 * sec, grace),
            Duration::from_secs(840)
        );
        assert_eq!(remaining_grace(Some(0), 1000 * sec, grace), Duration::ZERO);
        // A clock that moved backwards grants the whole period rather than underflowing.
        assert_eq!(remaining_grace(Some(100 * sec), 0, grace), grace);
    }
}
