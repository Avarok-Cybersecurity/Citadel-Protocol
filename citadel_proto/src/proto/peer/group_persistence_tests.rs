use super::*;
use citadel_types::proto::{GroupType, ReadPolicy};

fn group(hierarchy: GroupHierarchyMode) -> MessageGroup {
    PersistedGroup {
        owner: 1,
        options: MessageGroupOptions {
            group_type: GroupType::Private,
            id: 7,
            hierarchy,
            ephemeral: false,
            limits: None,
            retention: None,
            replay: None,
        },
        members: vec![1, 2],
        pending: vec![3],
        tree: 0,
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
