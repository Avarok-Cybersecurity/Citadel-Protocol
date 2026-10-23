use super::*;
use citadel_types::proto::{GroupType, ReadPolicy};

fn group(hierarchy: GroupHierarchyMode) -> MessageGroup {
    PersistedGroup {
        options: MessageGroupOptions {
            group_type: GroupType::Private,
            id: 7,
            hierarchy,
            ephemeral: false,
            limits: None,
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
