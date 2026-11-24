//! A replay group sends a member its own messages back, from the group's log, when it resumes.
//! These pin that a member opens its own ciphertext: once, under its own leaf, in either mode,
//! and from its stored state after a restart.

use super::*;
use citadel_types::proto::ReadPolicy;
use std::collections::HashMap;

fn flat_pair() -> (GroupCgkaState, GroupCgkaState) {
    let mut owner = GroupCgkaState::new_owner(1, GroupHierarchyMode::Flat).unwrap();
    let (mut member, kp) = GroupCgkaState::new_joiner(2, GroupHierarchyMode::Flat).unwrap();
    let (welcome, _commit, _epoch, _assign) = owner.add_member(&kp).unwrap();
    member.join(&welcome).unwrap();
    (owner, member)
}

#[test]
fn a_member_opens_its_own_message_once() {
    let (mut owner, mut member) = flat_pair();
    for (who, state) in [(2, &mut member), (1, &mut owner)] {
        let wire = state.encrypt_message(b"mine").unwrap();
        assert_eq!(state.decrypt_message(&wire).unwrap(), (who, b"mine".to_vec()));
        assert!(state.decrypt_message(&wire).is_err(), "opened twice");
    }
}

#[test]
fn a_member_opens_its_own_message_from_its_stored_state() {
    let (_owner, mut member) = flat_pair();
    let wire = member.encrypt_message(b"before the restart").unwrap();
    let stored = member.export().unwrap().expect("a member's state is exported");
    let mut restored = GroupCgkaState::import(&stored).unwrap();
    assert_eq!(
        restored.decrypt_message(&wire).unwrap(),
        (2, b"before the restart".to_vec())
    );
}

#[test]
fn a_member_of_a_command_hierarchy_opens_its_own_message() {
    let mut ranks = HashMap::new();
    let _ = ranks.insert(2, CommandPath::parse("/alpha"));
    let mode = GroupHierarchyMode::CommandHierarchy {
        read_policy: ReadPolicy::SuperiorOnly,
        ranks,
    };
    let mut owner = GroupCgkaState::new_owner(1, mode.clone()).unwrap();
    let (mut member, kp) = GroupCgkaState::new_joiner(2, mode).unwrap();
    let (welcome, _commit, _epoch, assign) = owner.add_member(&kp).unwrap();
    member.join(&welcome).unwrap();
    member.apply_hierarchy_assignment(&assign.unwrap()).unwrap();
    let wire = member.encrypt_message(b"own sitrep").unwrap();
    assert_eq!(member.decrypt_message(&wire).unwrap(), (2, b"own sitrep".to_vec()));
}
