//! The bytes a [`PersistedGroup`] is stored as.
//!
//! A group row is `(options, members, pending, relay, tree, owner)`: the options' three original fields first,
//! and the relay options (`ephemeral`, `limits`, `retention`) after `pending`. bincode has no field names, so
//! the order is the format. Every field is required: a row without its relay options, or with
//! caps that fail validation, is refused rather than read with defaults.

use crate::proto::peer::group_persistence::PersistedGroup;
use citadel_types::proto::{
    GroupHierarchyMode, GroupMessageLimits, GroupType, MessageGroupOptions,
};
use serde::{Deserialize, Serialize};

/// A group row.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredGroup {
    options: StoredOptions,
    members: Vec<u64>,
    pending: Vec<u64>,
    relay: StoredRelayOptions,
    tree: u64,
    owner: u64,
}

/// The option fields a row has always held, in their original order.
#[derive(Serialize, Deserialize)]
struct StoredOptions {
    group_type: GroupType,
    id: u128,
    hierarchy: GroupHierarchyMode,
}

/// The option fields that follow `pending`.
#[derive(Serialize, Deserialize)]
struct StoredRelayOptions {
    ephemeral: bool,
    limits: Option<GroupMessageLimits>,
    retention: Option<std::time::Duration>,
}

impl From<PersistedGroup> for StoredGroup {
    fn from(group: PersistedGroup) -> Self {
        let MessageGroupOptions {
            group_type,
            id,
            hierarchy,
            ephemeral,
            limits,
            retention,
        } = group.options;
        Self {
            options: StoredOptions {
                group_type,
                id,
                hierarchy,
            },
            members: group.members,
            pending: group.pending,
            tree: group.tree,
            owner: group.owner,
            relay: StoredRelayOptions {
                ephemeral,
                limits,
                retention,
            },
        }
    }
}

impl From<StoredGroup> for PersistedGroup {
    fn from(row: StoredGroup) -> Self {
        Self {
            options: MessageGroupOptions {
                group_type: row.options.group_type,
                id: row.options.id,
                hierarchy: row.options.hierarchy,
                ephemeral: row.relay.ephemeral,
                limits: row.relay.limits,
                retention: row.relay.retention,
            },
            members: row.members,
            pending: row.pending,
            tree: row.tree,
            owner: row.owner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_user::serialization::SyncIO;

    /// A row without its relay options.
    #[derive(Serialize, Deserialize)]
    struct RowWithoutRelayOptions {
        options: (GroupType, u128, GroupHierarchyMode),
        members: Vec<u64>,
        pending: Vec<u64>,
    }

    fn persisted(ephemeral: bool, limits: Option<GroupMessageLimits>) -> PersistedGroup {
        PersistedGroup {
            owner: 2,
            options: MessageGroupOptions {
                group_type: GroupType::Private,
                id: 7,
                hierarchy: GroupHierarchyMode::Flat,
                ephemeral,
                limits,
                retention: Some(std::time::Duration::from_secs(7)),
            },
            members: vec![1, 2],
            pending: vec![3],
            tree: 4,
        }
    }

    #[test]
    fn a_row_without_its_relay_options_is_refused() {
        let row = RowWithoutRelayOptions {
            options: (GroupType::Private, 7, GroupHierarchyMode::Flat),
            members: vec![1, 2],
            pending: vec![3],
        }
        .serialize_to_vector()
        .unwrap();
        assert!(PersistedGroup::deserialize_from_vector(&row).is_err());
    }

    #[test]
    fn the_relay_options_round_trip() {
        let limits = GroupMessageLimits::new(64, 2).ok();
        let bytes = persisted(true, limits).serialize_to_vector().unwrap();
        let read = PersistedGroup::deserialize_from_vector(&bytes).unwrap();
        assert!(read.options.ephemeral);
        assert_eq!(read.options.limits, limits);
        assert_eq!(
            read.options.retention,
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!((read.members, read.pending), (vec![1, 2], vec![3]));
        assert_eq!(read.tree, 4);
        assert_eq!(read.owner, 2);
    }
}
