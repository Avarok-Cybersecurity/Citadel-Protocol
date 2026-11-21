//! A commit or welcome received from the group is validated before it touches the member's tree:
//! every index must lie inside the tree, a refused commit leaves the member's state as it was, and
//! no input makes the tree walk run past its step bound. Each case must finish within a deadline,
//! in the release build as in the debug one.
use citadel_treekem::crypto::node_keypair_from_path_secret;
use citadel_treekem::node::{LeafNode, Node};
use citadel_treekem::ratchet_tree::RatchetTree;
use citadel_treekem::{Commit, GroupState, KeyPackage, Proposal, Welcome};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(10);

fn make_group(n: u32) -> Vec<GroupState> {
    let secrets: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
    let leaves = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| LeafNode {
            cid: i as u64 + 100,
            kem_public: node_keypair_from_path_secret(s).unwrap().0,
            sig_public: vec![],
            leaf_index: 0,
            signature: vec![],
        })
        .collect();
    let tree = RatchetTree::from_leaves(leaves);
    (0..n)
        .map(|i| GroupState::bootstrap(tree.clone(), i, secrets[i as usize], &[42u8; 32]))
        .collect()
}

/// `member` processes `commit` on another thread; the result must be an error, reached in time,
/// that left the member's epoch and tree as they were.
fn assert_refused_in_time(mut member: GroupState, commit: Commit) -> GroupState {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let before_tree = member.tree.clone();
        let before_epoch = member.epoch;
        let outcome = catch_unwind(AssertUnwindSafe(|| member.process_commit(&commit)));
        let _ = tx.send((
            outcome.map(|r| r.is_err()),
            before_tree,
            before_epoch,
            member,
        ));
    });
    let (outcome, before_tree, before_epoch, member) = rx
        .recv_timeout(DEADLINE)
        .expect("processing the commit did not finish within the deadline");
    assert!(
        outcome.expect("processing the commit panicked"),
        "commit must be refused"
    );
    assert_eq!(
        member.epoch, before_epoch,
        "a refused commit advanced the epoch"
    );
    assert_eq!(
        member.tree, before_tree,
        "a refused commit changed the tree"
    );
    member
}

#[test]
fn a_removal_outside_the_tree_is_refused() {
    let mut members = make_group(3);
    let mut commit = members[0].commit_update([0xAB; 32]).unwrap();
    commit.proposals = vec![Proposal::Remove { leaf_index: 1000 }];
    assert_refused_in_time(members.remove(1), commit);
}

#[test]
fn a_committer_outside_the_tree_is_refused() {
    let mut members = make_group(3);
    let mut commit = members[0].commit_update([0xAB; 32]).unwrap();
    commit.path.leaf_index = 1000;
    assert_refused_in_time(members.remove(1), commit);
}

#[test]
fn a_committer_at_the_largest_index_is_refused() {
    let mut members = make_group(3);
    let mut commit = members[0].commit_update([0xAB; 32]).unwrap();
    commit.path.leaf_index = u32::MAX;
    assert_refused_in_time(members.remove(1), commit);
}

#[test]
fn an_addition_past_the_next_slot_is_refused() {
    let mut members = make_group(3);
    let mut commit = members[0].commit_update([0xAB; 32]).unwrap();
    let key_package = KeyPackage::generate(999, &[9u8; 32]).unwrap();
    commit.proposals = vec![Proposal::Add {
        leaf: key_package.leaf.clone(),
        leaf_index: u32::MAX / 2,
    }];
    let member = assert_refused_in_time(members.remove(1), commit);
    assert_eq!(
        member.tree.nodes.len(),
        5,
        "a refused addition grew the tree"
    );
}

#[test]
fn an_addition_over_an_occupied_leaf_is_refused() {
    let mut members = make_group(3);
    let mut commit = members[0].commit_update([0xAB; 32]).unwrap();
    let key_package = KeyPackage::generate(999, &[9u8; 32]).unwrap();
    commit.proposals = vec![Proposal::Add {
        leaf: key_package.leaf.clone(),
        leaf_index: 2,
    }];
    assert_refused_in_time(members.remove(1), commit);
}

#[test]
fn a_refused_commit_leaves_the_member_able_to_follow_the_genuine_one() {
    let mut members = make_group(3);
    let genuine = members[0].commit_update([0xAB; 32]).unwrap();
    let mut corrupt = genuine.clone();
    for node in &mut corrupt.path.nodes {
        for ct in &mut node.encrypted_path_secrets {
            for b in ct.aead_ct.iter_mut() {
                *b ^= 0xFF;
            }
        }
    }
    let mut member = assert_refused_in_time(members.remove(1), corrupt);
    member.process_commit(&genuine).unwrap();
    assert_eq!(member.encryption_secret(), members[0].encryption_secret());
}

fn welcome_for_new_member() -> (Welcome, [u8; 32]) {
    let founder_secret = [1u8; 32];
    let founder_leaf = LeafNode {
        cid: 1,
        kem_public: node_keypair_from_path_secret(&founder_secret).unwrap().0,
        sig_public: vec![],
        leaf_index: 0,
        signature: vec![],
    };
    let mut founder = GroupState::create(founder_leaf, founder_secret);
    let joiner_secret = [2u8; 32];
    let key_package = KeyPackage::generate(2, &joiner_secret).unwrap();
    let (_commit, welcome) = founder.add_member(&key_package, [3u8; 32]).unwrap();
    (welcome, joiner_secret)
}

fn assert_welcome_refused(welcome: Welcome, secret: [u8; 32]) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            GroupState::join_from_welcome(&welcome, secret).is_err()
        }));
        let _ = tx.send(outcome);
    });
    let outcome = rx
        .recv_timeout(DEADLINE)
        .expect("joining did not finish within the deadline");
    assert!(
        outcome.expect("joining panicked"),
        "welcome must be refused"
    );
}

#[test]
fn a_genuine_welcome_is_accepted() {
    let (welcome, secret) = welcome_for_new_member();
    assert!(GroupState::join_from_welcome(&welcome, secret).is_ok());
}

#[test]
fn a_welcome_naming_a_leaf_outside_its_tree_is_refused() {
    let (mut welcome, secret) = welcome_for_new_member();
    welcome.joiner_leaf_index = u32::MAX;
    assert_welcome_refused(welcome, secret);
}

#[test]
fn a_welcome_with_a_tree_of_even_width_is_refused() {
    let (mut welcome, secret) = welcome_for_new_member();
    welcome.group_info.tree.nodes.push(Node::Blank);
    assert_welcome_refused(welcome, secret);
}

#[test]
fn a_welcome_whose_unmerged_leaves_leave_the_tree_is_refused() {
    let (mut welcome, secret) = welcome_for_new_member();
    welcome.group_info.tree.nodes[1] = Node::Parent {
        kem_public: vec![1],
        parent_hash: [0u8; 32],
        unmerged_leaves: vec![u32::MAX],
    };
    assert_welcome_refused(welcome, secret);
}
