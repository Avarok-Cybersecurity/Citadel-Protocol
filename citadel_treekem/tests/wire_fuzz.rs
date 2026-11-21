//! Bytes received from the group, however malformed, are refused or applied without panicking and
//! within a time bound: commits, welcomes, application messages and hierarchy envelopes.
mod support;

use citadel_treekem::crypto::node_keypair_from_path_secret;
use citadel_treekem::node::LeafNode;
use citadel_treekem::{
    AppCiphertext, CommandPath, Commit, GroupState, HierarchyMember, KeyPackage, ReadPolicy,
    Welcome,
};
use std::time::Duration;
use support::wire_fuzz::campaign;

const CASES: usize = 2_000;
const DEADLINE: Duration = Duration::from_secs(120);

fn leaf(cid: u64, secret: &[u8; 32]) -> LeafNode {
    KeyPackage::generate(cid, secret).unwrap().leaf
}

/// A founder with two joined members, and the encodings of what the group sends one another.
struct Fixture {
    member: GroupState,
    joiner_secret: [u8; 32],
    commit: Vec<u8>,
    add_commit: Vec<u8>,
    welcome: Vec<u8>,
    message: Vec<u8>,
}

fn fixture() -> Fixture {
    let mut founder = GroupState::create(leaf(1, &[1u8; 32]), [1u8; 32]);
    let (_c, welcome_b) = founder
        .add_member(&KeyPackage::generate(2, &[2u8; 32]).unwrap(), [3u8; 32])
        .unwrap();
    let member = GroupState::join_from_welcome(&welcome_b, [2u8; 32]).unwrap();
    let joiner_secret = [4u8; 32];
    let (add_commit, welcome) = founder
        .add_member(&KeyPackage::generate(3, &joiner_secret).unwrap(), [5u8; 32])
        .unwrap();
    let mut member_after_add = member.clone();
    member_after_add.process_commit(&add_commit).unwrap();
    let commit = founder.commit_update([6u8; 32]).unwrap();
    let message = founder.encrypt_message(b"hello").unwrap();
    Fixture {
        member,
        joiner_secret,
        commit: bincode::serialize(&commit).unwrap(),
        add_commit: bincode::serialize(&add_commit).unwrap(),
        welcome: bincode::serialize(&welcome).unwrap(),
        message: bincode::serialize(&message).unwrap(),
    }
}

#[test]
fn received_commits_never_panic_or_spin() {
    let f = fixture();
    let member = f.member;
    campaign(
        "commit",
        vec![f.commit, f.add_commit],
        CASES,
        DEADLINE,
        move |bytes| {
            if let Ok(commit) = citadel_io::decode::deserialize::<Commit>(bytes) {
                let mut state = member.clone();
                let before = state.tree.clone();
                if state.process_commit(&commit).is_err() {
                    assert_eq!(state.tree, before, "a refused commit changed the tree");
                }
            }
        },
    );
}

#[test]
fn received_welcomes_never_panic_or_spin() {
    let f = fixture();
    let secret = f.joiner_secret;
    campaign("welcome", vec![f.welcome], CASES, DEADLINE, move |bytes| {
        if let Ok(welcome) = citadel_io::decode::deserialize::<Welcome>(bytes) {
            let _ = GroupState::join_from_welcome(&welcome, secret);
        }
    });
}

#[test]
fn received_application_messages_never_panic() {
    let f = fixture();
    let member = f.member;
    campaign("message", vec![f.message], CASES, DEADLINE, move |bytes| {
        if let Ok(message) = citadel_io::decode::deserialize::<AppCiphertext>(bytes) {
            let _ = member.clone().decrypt_message(&message);
        }
    });
}

#[test]
fn received_hierarchy_envelopes_never_panic() {
    let root = HierarchyMember::root([7u8; 32], ReadPolicy::BroadcastAudit);
    let member = root
        .derive_descendant(CommandPath::parse("/HQ/Bn1"))
        .unwrap();
    let leaf_secret = [8u8; 32];
    let (leaf_pk, _) = node_keypair_from_path_secret(&leaf_secret).unwrap();
    let sealed = member.seal_to(&leaf_pk).unwrap();
    let flat = [9u8; 32];
    let envelope = member
        .seal_message(Some(&flat), &[10u8; 32], b"sitrep")
        .unwrap();
    campaign(
        "hierarchy",
        vec![sealed, envelope],
        CASES,
        DEADLINE,
        move |bytes| {
            let _ = HierarchyMember::open(bytes, &leaf_secret);
            let _ = root.open_message(Some(&flat), bytes);
        },
    );
}
