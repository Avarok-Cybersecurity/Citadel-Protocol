//! End-to-end proof that the two pipelined-PFS crypto primitives compose into per-message
//! forward-secure encryption, BEFORE they are wired into the live ratchet
//! (`docs/pfs-symmetric-ratchet-design.md`). The sender advances a `SymmetricChain` to get
//! `(i, MK_i)` and seals with `MK_i` via the per-message AEAD; the receiver derives the same `MK_i`
//! from its mirror chain and opens. Each message is encrypted under a distinct, forward-secure key
//! with NO network round-trip — the whole point of the design.

use citadel_crypt::ratchets::message_chain::SymmetricChain;
use citadel_pqcrypto::per_message_aead::{open_in_place_with_key, seal_in_place_with_key};
use citadel_types::crypto::EncryptionAlgorithm;

const A2B: &[u8] = b"a2b";
const MAX_SKIP: u64 = 1024;
const NONCE: [u8; 16] = [0x5a; 16];

fn roundtrip_pipeline(alg: EncryptionAlgorithm) {
    // Both endpoints seed identically from the (shared) per-version root + direction label.
    let root = [0x42u8; 32];
    let mut sender = SymmetricChain::new(&root, A2B);
    let mut receiver = SymmetricChain::new(&root, A2B);

    for n in 0..500usize {
        let plaintext = format!("message #{n} under {alg:?}").into_bytes();

        // Sender: fresh forward-secure key for this message, then seal.
        let (idx, mk_send) = sender.next_send_key();
        let mut wire = plaintext.clone();
        seal_in_place_with_key(alg, &mk_send[..], &NONCE, b"aad", &mut wire).unwrap();
        assert_ne!(wire, plaintext);

        // Receiver: derive the same key from the index, then open.
        let mk_recv = receiver.recv_key(idx, MAX_SKIP).unwrap();
        assert_eq!(
            &mk_send[..],
            &mk_recv[..],
            "{alg:?}: chain keys diverged at {idx}"
        );
        open_in_place_with_key(alg, &mk_recv[..], &NONCE, b"aad", &mut wire).unwrap();
        assert_eq!(
            wire, plaintext,
            "{alg:?}: end-to-end roundtrip failed at {idx}"
        );
    }
}

#[test]
fn end_to_end_per_message_forward_secure_roundtrip() {
    roundtrip_pipeline(EncryptionAlgorithm::AES_GCM_256);
    roundtrip_pipeline(EncryptionAlgorithm::ChaCha20Poly_1305);
    roundtrip_pipeline(EncryptionAlgorithm::Ascon80pq);
}

#[test]
fn out_of_order_delivery_still_opens() {
    let root = [0x11u8; 32];
    let alg = EncryptionAlgorithm::AES_GCM_256;
    let mut sender = SymmetricChain::new(&root, A2B);
    let mut receiver = SymmetricChain::new(&root, A2B);

    // Seal 20 messages on the wire in order.
    let mut on_wire: Vec<(u64, Vec<u8>)> = Vec::new();
    for n in 0..20u64 {
        let (idx, mk) = sender.next_send_key();
        let mut buf = format!("ooo-{n}").into_bytes();
        seal_in_place_with_key(alg, &mk[..], &NONCE, b"", &mut buf).unwrap();
        on_wire.push((idx, buf));
    }

    // Deliver them to the receiver out of order (reverse) — the skipped-key cache must cover it.
    for (idx, mut buf) in on_wire.into_iter().rev() {
        let mk = receiver.recv_key(idx, MAX_SKIP).unwrap();
        open_in_place_with_key(alg, &mk[..], &NONCE, b"", &mut buf).unwrap();
        assert_eq!(buf, format!("ooo-{idx}").into_bytes());
    }
}

#[test]
fn wrong_direction_chain_cannot_open() {
    // A receiver seeded for the opposite direction derives different keys and must NOT decrypt — this
    // is what keeps the two directions cryptographically independent.
    let root = [0x33u8; 32];
    let alg = EncryptionAlgorithm::ChaCha20Poly_1305;
    let mut sender = SymmetricChain::new(&root, b"a2b");
    let mut wrong = SymmetricChain::new(&root, b"b2a");

    let (idx, mk) = sender.next_send_key();
    let mut buf = b"top secret".to_vec();
    seal_in_place_with_key(alg, &mk[..], &NONCE, b"", &mut buf).unwrap();

    let wrong_mk = wrong.recv_key(idx, MAX_SKIP).unwrap();
    assert!(
        open_in_place_with_key(alg, &wrong_mk[..], &NONCE, b"", &mut buf).is_err(),
        "opposite-direction chain must not decrypt"
    );
}
