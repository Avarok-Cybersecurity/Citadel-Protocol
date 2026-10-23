//! The bytes a [`PersistedGroup`] is stored as.
//!
//! A group row was written as `(options, members, pending)`, with the options' three original
//! fields first. The options have since gained fields (`ephemeral`, `limits`), and bincode has no
//! field names: storing the options as they are now would put the new fields between `options`
//! and `members`, where a row written before them holds the members, so an old row would decode
//! into garbage. The row therefore keeps its original layout, and the new option fields are
//! appended after `pending`, read as their defaults from a row that predates them.

use crate::proto::peer::group_persistence::PersistedGroup;
use citadel_types::proto::{
    GroupHierarchyMode, GroupMessageLimits, GroupType, MessageGroupOptions,
};
use citadel_types::wire_compat::ok_or_default;
use serde::{Deserialize, Serialize};

/// A group row, in the layout every row has had.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredGroup {
    options: StoredOptions,
    members: Vec<u64>,
    pending: Vec<u64>,
    #[serde(default, deserialize_with = "ok_or_default")]
    relay: StoredRelayOptions,
}

/// The option fields a row has always held, in their original order.
#[derive(Serialize, Deserialize)]
struct StoredOptions {
    group_type: GroupType,
    id: u128,
    hierarchy: GroupHierarchyMode,
}

/// The option fields appended to the row.
#[derive(Serialize, Deserialize, Default)]
struct StoredRelayOptions {
    ephemeral: bool,
    limits: Option<GroupMessageLimits>,
}

impl From<PersistedGroup> for StoredGroup {
    fn from(group: PersistedGroup) -> Self {
        let MessageGroupOptions {
            group_type,
            id,
            hierarchy,
            ephemeral,
            limits,
        } = group.options;
        Self {
            options: StoredOptions {
                group_type,
                id,
                hierarchy,
            },
            members: group.members,
            pending: group.pending,
            relay: StoredRelayOptions { ephemeral, limits },
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
            },
            members: row.members,
            pending: row.pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_user::serialization::SyncIO;

    /// A row exactly as a server before the relay options wrote it.
    #[derive(Serialize, Deserialize)]
    struct RowBeforeRelayOptions {
        options: (GroupType, u128, GroupHierarchyMode),
        members: Vec<u64>,
        pending: Vec<u64>,
    }

    fn persisted(ephemeral: bool, limits: Option<GroupMessageLimits>) -> PersistedGroup {
        PersistedGroup {
            options: MessageGroupOptions {
                group_type: GroupType::Private,
                id: 7,
                hierarchy: GroupHierarchyMode::Flat,
                ephemeral,
                limits,
            },
            members: vec![1, 2],
            pending: vec![3],
        }
    }

    #[test]
    fn a_row_written_before_the_relay_options_reads_as_an_ordinary_group() {
        let old = RowBeforeRelayOptions {
            options: (GroupType::Private, 7, GroupHierarchyMode::Flat),
            members: vec![1, 2],
            pending: vec![3],
        }
        .serialize_to_vector()
        .unwrap();
        let read = PersistedGroup::deserialize_from_vector(&old).unwrap();
        assert_eq!(
            (read.options.id, read.members, read.pending),
            (7, vec![1, 2], vec![3])
        );
        assert!(!read.options.ephemeral);
        assert_eq!(read.options.limits, None);
    }

    #[test]
    fn the_relay_options_round_trip_and_follow_the_original_layout() {
        let limits = GroupMessageLimits::new(64, 2).ok();
        let bytes = persisted(true, limits).serialize_to_vector().unwrap();
        let read = PersistedGroup::deserialize_from_vector(&bytes).unwrap();
        assert!(read.options.ephemeral);
        assert_eq!(read.options.limits, limits);
        let old_layout = RowBeforeRelayOptions {
            options: (GroupType::Private, 7, GroupHierarchyMode::Flat),
            members: vec![1, 2],
            pending: vec![3],
        }
        .serialize_to_vector()
        .unwrap();
        assert!(
            bytes.starts_with(&old_layout),
            "an older server reads the row it always wrote, and ignores the rest"
        );
    }
}
