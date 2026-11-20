//! The KEM suite of a group's tree keys. A group whose members all run this release keys its tree
//! on ML-KEM-1024. A member that publishes only a round-3 key, as every release before 0.12.4 does,
//! still joins and follows, and every node it must open stays on round 3 while it is a member.

use citadel_treekem::crypto::{suite_of, CURRENT_SUITE, ROUND_3_SUITE};
use citadel_treekem::math::direct_path;
use citadel_treekem::node::{LeafNode, Node};
use citadel_treekem::{Commit, GroupState, KeyPackage, Proposal};
use citadel_types::crypto::KemAlgorithm;
use serde::{Deserialize, Serialize};

/// A key package as a joiner before 0.12.4 publishes it: a round-3 leaf and nothing after it.
fn earlier_joiner(cid: u64, leaf_secret: &[u8; 32]) -> KeyPackage {
    KeyPackage {
        current_kem_public: None,
        ..KeyPackage::generate(cid, leaf_secret).unwrap()
    }
}

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
    follow(members, &commit);
    GroupState::join_from_welcome(&welcome, secret).unwrap()
}

fn follow(members: &mut [GroupState], commit: &Commit) {
    for member in members {
        member.process_commit(commit).unwrap();
    }
}

/// The suite of every key the owner's last commit derived: its leaf and its direct path.
fn suites_of_owner_path(owner: &GroupState) -> Vec<KemAlgorithm> {
    let n = owner.tree.num_leaves();
    let leaf = citadel_treekem::math::leaf_to_node(owner.own_leaf);
    std::iter::once(leaf)
        .chain(direct_path(owner.own_leaf, n).unwrap())
        .filter_map(|x| owner.tree.get(x).unwrap().kem_public().map(<[u8]>::to_vec))
        .map(|pk| suite_of(&pk).unwrap())
        .collect()
}

fn assert_all_read(sender: &mut GroupState, readers: &[&GroupState]) {
    let sealed = sender.encrypt_message(b"status").unwrap();
    for reader in readers {
        assert_eq!(reader.decrypt_message(&sealed).unwrap(), b"status");
    }
}

#[test]
fn a_group_of_current_members_keys_its_tree_on_ml_kem_1024() {
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

    for x in 0..owner.tree.nodes.len() as u32 {
        if let Some(pk) = owner.tree.get(x).unwrap().kem_public() {
            assert_eq!(suite_of(pk).unwrap(), CURRENT_SUITE, "node {x}");
        }
    }
    assert_eq!(owner.sealing_suite(), CURRENT_SUITE);
    assert_all_read(&mut owner, &[&b, &c]);
}

#[test]
fn a_member_from_before_0_12_4_is_only_ever_asked_to_open_round_3_keys() {
    let mut owner = owner();
    let b = add(
        &mut owner,
        &mut [],
        &KeyPackage::generate(2, &[2u8; 32]).unwrap(),
        [2u8; 32],
    );
    assert!(suites_of_owner_path(&owner)
        .iter()
        .all(|s| *s == CURRENT_SUITE));

    let mut members = [b];
    let old = add(
        &mut owner,
        &mut members,
        &earlier_joiner(3, &[3u8; 32]),
        [3u8; 32],
    );
    let old_leaf = old.tree.leaf_of_cid(3).unwrap().kem_public.clone();
    assert_eq!(suite_of(&old_leaf).unwrap(), ROUND_3_SUITE, "its own leaf");
    assert!(
        suites_of_owner_path(&owner)
            .iter()
            .all(|s| *s == ROUND_3_SUITE),
        "the path it learns"
    );
    assert_eq!(owner.sealing_suite(), ROUND_3_SUITE, "what superiors open");

    let [b] = members;
    let mut members = [b, old];
    let update = owner.commit_update([0xB1; 32]).unwrap();
    follow(&mut members, &update);
    assert!(suites_of_owner_path(&owner)
        .iter()
        .all(|s| *s == ROUND_3_SUITE));
    assert_all_read(&mut owner, &[&members[0], &members[1]]);

    // Once it leaves, the next commit moves the owner's path to ML-KEM-1024.
    let [mut b, _old] = members;
    let leaf = owner.tree.leaf_index_of_cid(3).unwrap();
    let removal = owner.remove_member(leaf, [0xB2; 32]).unwrap();
    b.process_commit(&removal).unwrap();
    assert!(suites_of_owner_path(&owner)
        .iter()
        .all(|s| *s == CURRENT_SUITE));
    assert_all_read(&mut owner, &[&b]);
}

/// The layouts a release before 0.12.4 reads and writes.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct EarlierKeyPackage {
    leaf: LeafNode,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum EarlierProposal {
    Add {
        key_package: EarlierKeyPackage,
        leaf_index: u32,
    },
    Remove {
        leaf_index: u32,
    },
}

#[test]
fn key_packages_and_additions_keep_the_layout_earlier_releases_read() {
    let current = KeyPackage::generate(7, &[7u8; 32]).unwrap();
    let bytes = bincode::serialize(&current).unwrap();
    let read_by_earlier: EarlierKeyPackage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(
        read_by_earlier.leaf, current.leaf,
        "an earlier owner reads the round-3 leaf"
    );

    let from_earlier = bincode::serialize(&EarlierKeyPackage {
        leaf: current.leaf.clone(),
    })
    .unwrap();
    let read: KeyPackage = bincode::deserialize(&from_earlier).unwrap();
    assert_eq!(read.current_kem_public, None);
    assert_eq!(read.leaf_to_insert(), current.leaf);

    let leaf = current.leaf_to_insert();
    let added = bincode::serialize(&Proposal::Add {
        leaf: leaf.clone(),
        leaf_index: 4,
    })
    .unwrap();
    let earlier = bincode::serialize(&EarlierProposal::Add {
        key_package: EarlierKeyPackage { leaf },
        leaf_index: 4,
    })
    .unwrap();
    assert_eq!(added, earlier);
}

#[test]
fn a_tree_node_of_no_tree_suite_is_refused() {
    let mut owner = owner();
    let mut kp = KeyPackage::generate(2, &[2u8; 32]).unwrap();
    kp.current_kem_public = Some(vec![0u8; 1000]);
    assert!(owner.add_member(&kp, [0xC0; 32]).is_err());
    assert!(matches!(owner.tree.get(0).unwrap(), Node::Leaf(_)));
    assert_eq!(
        owner.tree.num_leaves(),
        1,
        "a refused package leaves the group as it was"
    );
}
