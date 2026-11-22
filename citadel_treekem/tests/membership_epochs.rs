//! A message sealed at the epoch a member holds when another member is removed is still read by
//! the members that remain; the removed member's own messages of that epoch are not.

use citadel_treekem::{GroupState, KeyPackage};

/// The owner (leaf 0) with members B (leaf 1) and C (leaf 2), all at the same epoch.
fn trio() -> (GroupState, GroupState, GroupState) {
    let (a_secret, b_secret, c_secret) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let mut a = GroupState::create(KeyPackage::generate(1, &a_secret).unwrap().leaf, a_secret);
    let (_, welcome_b) = a
        .add_member(&KeyPackage::generate(2, &b_secret).unwrap(), [9u8; 32])
        .unwrap();
    let mut b = GroupState::join_from_welcome(&welcome_b, b_secret).unwrap();
    let (commit_c, welcome_c) = a
        .add_member(&KeyPackage::generate(3, &c_secret).unwrap(), [8u8; 32])
        .unwrap();
    b.process_commit(&commit_c).unwrap();
    let c = GroupState::join_from_welcome(&welcome_c, c_secret).unwrap();
    (a, b, c)
}

#[test]
fn a_message_in_flight_across_a_removal_is_read_by_the_members_that_remain() {
    let (mut a, mut b, mut c) = trio();
    let from_b = b.encrypt_message(b"sent before b saw the removal").unwrap();
    let from_c = c.encrypt_message(b"sent by the member removed").unwrap();
    let removal = a.remove_member(c.own_leaf, [7u8; 32]).unwrap();

    assert_eq!(
        a.decrypt_message(&from_b).unwrap().plaintext,
        b"sent before b saw the removal"
    );
    assert!(
        a.decrypt_message(&from_c).is_err(),
        "a removed member was read at the epoch it left"
    );
    b.process_commit(&removal).unwrap();
    let after = a.encrypt_message(b"after").unwrap();
    assert_eq!(b.decrypt_message(&after).unwrap().plaintext, b"after");
    assert!(c.decrypt_message(&after).is_err());
}

#[test]
fn a_re_key_retires_the_epoch_it_leaves() {
    let (mut a, mut b, _c) = trio();
    let from_b = b.encrypt_message(b"old epoch").unwrap();
    let _ = a.commit_update([6u8; 32]).unwrap();
    assert!(a.decrypt_message(&from_b).is_err());
}

/// A commit replaces the committer's leaf keys, its signing key among them: a copy of the
/// committer's state from before the commit (another device that held it) signs nothing the
/// group accepts, even at an epoch the remaining members still read.
#[test]
fn a_copy_of_the_committers_previous_leaf_signs_nothing_the_group_accepts() {
    let (mut a, mut b, c) = trio();
    let mut old_copy = GroupState::import(&a.export().unwrap(), 1).unwrap();
    let removal = a.remove_member(c.own_leaf, [7u8; 32]).unwrap();
    b.process_commit(&removal).unwrap();

    let forged = old_copy.encrypt_message(b"from the old leaf").unwrap();
    assert!(
        b.decrypt_message(&forged).is_err(),
        "a copy of the committer's previous leaf was accepted"
    );
    let live = a.encrypt_message(b"from the live leaf").unwrap();
    assert_eq!(
        b.decrypt_message(&live).unwrap().plaintext,
        b"from the live leaf"
    );
}

/// A member's message in flight across the committer replacing its own leaf is still read, and
/// a copy of the committer's previous leaf is shut out of the new epoch and of the one it left.
#[test]
fn a_leaf_replacement_keeps_messages_in_flight_and_shuts_out_the_old_leaf() {
    let (mut a, mut b, _c) = trio();
    let mut old_copy = GroupState::import(&a.export().unwrap(), 1).unwrap();
    let in_flight = b
        .encrypt_message(b"sent before b saw the replacement")
        .unwrap();
    let replacement = a.replace_own_leaf([5u8; 32]).unwrap();
    assert_eq!(
        a.decrypt_message(&in_flight).unwrap().plaintext,
        b"sent before b saw the replacement"
    );
    b.process_commit(&replacement).unwrap();
    let after = a.encrypt_message(b"after").unwrap();
    assert_eq!(b.decrypt_message(&after).unwrap().plaintext, b"after");
    assert!(old_copy.decrypt_message(&after).is_err());
    let forged = old_copy.encrypt_message(b"from the old leaf").unwrap();
    assert!(b.decrypt_message(&forged).is_err());
}

#[test]
fn an_update_for_another_members_leaf_is_refused() {
    let (mut a, mut b, c) = trio();
    let mut replacement = a.replace_own_leaf([5u8; 32]).unwrap();
    replacement.proposals = vec![citadel_treekem::Proposal::Update {
        leaf_index: c.own_leaf,
    }];
    assert!(b.process_commit(&replacement).is_err());
}
