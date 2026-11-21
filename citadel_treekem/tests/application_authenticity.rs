//! A member opens an application message only as the member that sealed it, and only once.
//!
//! Every member holds the epoch's encryption secret, so the message key of any `(sender,
//! generation)` is one any member can derive. A message is therefore accepted only when it
//! proves its sender's leaf made it, and a message already opened is not opened again.
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use citadel_treekem::{AppCiphertext, GroupState, KeyPackage};

/// The owner (leaf 0) with members B (leaf 1) and C (leaf 2), all at the same epoch.
fn trio() -> (GroupState, GroupState, GroupState) {
    let (a_secret, b_secret, c_secret) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let a_leaf = KeyPackage::generate(1, &a_secret).unwrap().leaf;
    let mut a = GroupState::create(a_leaf, a_secret);
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

/// What a member that knows the epoch's encryption secret can seal under another's leaf.
fn sealed_as(epoch_secret: &[u8; 32], leaf: u32, generation: u32) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-app-message-v2");
    hasher.update(epoch_secret);
    hasher.update(&leaf.to_be_bytes());
    hasher.update(&0u64.to_be_bytes()); // incarnation
    hasher.update(&generation.to_be_bytes());
    let mut out = [0u8; 44];
    hasher.finalize_xof().fill(&mut out);
    let cipher = ChaCha20Poly1305::new_from_slice(&out[..32]).unwrap();
    let nonce = Nonce::from_slice(&out[32..44]);
    cipher
        .encrypt(nonce, b"sent as the owner".as_ref())
        .unwrap()
}

#[test]
fn a_member_cannot_seal_a_message_as_another_member() {
    let (a, b, mut c) = trio();
    let forged = AppCiphertext {
        epoch: b.epoch,
        sender: a.own_leaf,
        incarnation: 0,
        generation: 7,
        ciphertext: sealed_as(b.encryption_secret(), a.own_leaf, 7),
        signature: b"not the owner's".to_vec(),
    };
    assert!(
        c.decrypt_message(&forged).is_err(),
        "C opened, as the owner's, a message B sealed"
    );
}

#[test]
fn a_message_is_opened_once() {
    let (mut a, _b, mut c) = trio();
    let sent = a.encrypt_message(b"once").unwrap();
    assert_eq!(c.decrypt_message(&sent).unwrap().plaintext, b"once");
    assert!(
        c.decrypt_message(&sent).is_err(),
        "the same message was opened twice"
    );
}
