//! The KEM suite of a group's tree keys. Every key a tree holds is ML-KEM-1024: a key package,
//! an added leaf or a path key of any other KEM is refused, naming that KEM, before it changes
//! the group.

use citadel_treekem::crypto::{suite_of, CURRENT_SUITE};
use citadel_treekem::{Commit, GroupState, KeyPackage, Proposal};
use citadel_types::crypto::KemAlgorithm;

/// An owner founded from its own key package, as `GroupCgkaState::new_owner` founds one.
fn owner() -> GroupState {
    let secret = [1u8; 32];
    GroupState::create(KeyPackage::generate(1, &secret).unwrap().leaf, secret)
}

/// The owner adds `kp` and every current member follows the commit; returns the joiner.
fn add(
    owner: &mut GroupState,
    members: &mut [GroupState],
    kp: &KeyPackage,
    secret: [u8; 32],
) -> GroupState {
    let (commit, welcome) = owner.add_member(kp, [0xA0 ^ secret[0]; 32]).unwrap();
    for member in members {
        member.process_commit(&commit).unwrap();
    }
    GroupState::join_from_welcome(&welcome, secret).unwrap()
}

/// A public key of a KEM other than the tree's: ML-KEM-768, whose keys have the length the
/// round-3 suite's keys had.
fn key_of_another_kem() -> Vec<u8> {
    citadel_pqcrypto::kem_keypair_from_seed(KemAlgorithm::MlKem768Fips203, &[4u8; 64])
        .unwrap()
        .0
}

fn assert_refused_by_name(outcome: Result<(), citadel_types::errors::Error>) {
    let refusal = outcome.expect_err("must be refused").to_string();
    assert!(
        refusal.contains(
            "a MlKem768Fips203 KEM public key is refused; a tree runs only on MlKem1024Fips203"
        ),
        "{refusal}"
    );
}

#[test]
fn a_group_keys_its_whole_tree_on_ml_kem_1024() {
    let mut owner = owner();
    let b = add(
        &mut owner,
        &mut [],
        &KeyPackage::generate(2, &[2u8; 32]).unwrap(),
        [2u8; 32],
    );
    let mut members = [b];
    let c = add(
        &mut owner,
        &mut members,
        &KeyPackage::generate(3, &[3u8; 32]).unwrap(),
        [3u8; 32],
    );
    let [b] = members;

    let mut keys = 0;
    for x in 0..owner.tree.nodes.len() as u32 {
        if let Some(pk) = owner.tree.get(x).unwrap().kem_public() {
            assert_eq!(suite_of(pk).unwrap(), CURRENT_SUITE, "node {x}");
            keys += 1;
        }
    }
    assert!(keys >= 4, "three leaves and the owner's path: {keys}");
    let sealed = owner.encrypt_message(b"status").unwrap();
    for reader in [&b, &c] {
        assert_eq!(reader.decrypt_message(&sealed).unwrap(), b"status");
    }
}

#[test]
fn a_key_package_of_another_kem_is_refused_by_name() {
    let mut owner = owner();
    for (key, named) in [(key_of_another_kem(), true), (vec![0u8; 1000], false)] {
        let mut kp = KeyPackage::generate(2, &[2u8; 32]).unwrap();
        kp.leaf.kem_public = key;
        let outcome = owner.add_member(&kp, [0xC0; 32]).map(|_| ());
        if named {
            assert_refused_by_name(outcome);
        } else {
            assert!(outcome.is_err());
        }
        assert_eq!(
            (owner.tree.num_leaves(), owner.epoch),
            (1, 0),
            "a refused package leaves the group as it was"
        );
    }
}

/// A commit from the owner, adding a fresh member, that `edit` alters before `member` sees it.
fn altered_commit(edit: impl FnOnce(&mut Commit)) -> (GroupState, Commit) {
    let mut owner = owner();
    let member = add(
        &mut owner,
        &mut [],
        &KeyPackage::generate(2, &[2u8; 32]).unwrap(),
        [2u8; 32],
    );
    let (mut commit, _welcome) = owner
        .add_member(&KeyPackage::generate(3, &[3u8; 32]).unwrap(), [0xD0; 32])
        .unwrap();
    edit(&mut commit);
    (member, commit)
}

fn assert_member_refuses(edit: impl FnOnce(&mut Commit)) {
    let (mut member, commit) = altered_commit(edit);
    let (tree, epoch) = (member.tree.clone(), member.epoch);
    assert_refused_by_name(member.process_commit(&commit));
    assert_eq!(member.epoch, epoch, "a refused commit advanced the epoch");
    assert_eq!(member.tree, tree, "a refused commit changed the tree");
}

#[test]
fn a_member_refuses_an_added_leaf_of_another_kem_by_name() {
    assert_member_refuses(|commit| {
        for proposal in &mut commit.proposals {
            if let Proposal::Add { leaf, .. } = proposal {
                leaf.kem_public = key_of_another_kem();
            }
        }
    });
}

#[test]
fn a_member_refuses_a_path_key_of_another_kem_by_name() {
    assert_member_refuses(|commit| commit.path.leaf_kem_public = key_of_another_kem());
    assert_member_refuses(|commit| commit.path.nodes[0].kem_public = key_of_another_kem());
}

/// The control for the refusals above: the same commit, unaltered, is followed.
#[test]
fn a_member_follows_the_unaltered_commit() {
    let (mut member, commit) = altered_commit(|_| ());
    member.process_commit(&commit).unwrap();
}
