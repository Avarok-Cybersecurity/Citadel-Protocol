//! WASM crypto tests — validate that core cryptographic operations
//! work correctly on `wasm32-unknown-unknown`.
//!
//! These complement the native-only tests in `primary.rs` by exercising
//! code paths that previously panicked on WASM (e.g., `std::time::Instant`).
#![cfg(target_family = "wasm")]

use bytes::{BufMut, BytesMut};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::prelude::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm};
use wasm_bindgen_test::*;

/// Create an Alice/Bob ratchet pair for testing.
fn create_ratchet_pair(
    algorithm: CryptoParameters,
    security_level: SecurityLevel,
) -> (StackedRatchet, StackedRatchet) {
    let cid = 1000u64;
    let version = 0u32;

    let mut alice = <StackedRatchet as Ratchet>::Constructor::new_alice(
        ConstructorOpts::new_vec_init(Some(algorithm), security_level),
        cid,
        version,
    )
    .expect("Alice constructor");

    let mut bob = <StackedRatchet as Ratchet>::Constructor::new_bob(
        cid,
        ConstructorOpts::new_vec_init(Some(algorithm), security_level),
        alice.stage0_alice().expect("stage0_alice"),
        &[] as &[Vec<u8>],
    )
    .expect("Bob constructor");

    let bob_transfer = bob.stage0_bob().expect("stage0_bob");
    alice
        .stage1_alice(bob_transfer, &[] as &[Vec<u8>])
        .expect("stage1_alice");

    (
        alice.finish().expect("Alice finish"),
        bob.finish().expect("Bob finish"),
    )
}

/// Verify that StackedRatchet construction works on WASM for all algorithm combos.
#[wasm_bindgen_test]
fn test_ratchet_construction_all_algorithms() {
    let algorithms = [
        EncryptionAlgorithm::AES_GCM_256,
        EncryptionAlgorithm::ChaCha20Poly_1305,
    ];
    let kems = [KemAlgorithm::MlKem];

    for enc in &algorithms {
        for kem in &kems {
            let params = *enc + *kem;
            let (alice, bob) = create_ratchet_pair(params, SecurityLevel::Standard);
            assert_eq!(alice.version(), bob.version());
        }
    }
}

/// Encrypt with Alice, decrypt with Bob — validates the full protect/validate cycle.
#[wasm_bindgen_test]
fn test_encrypt_decrypt_roundtrip() {
    let params = EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem;
    let (alice, bob) = create_ratchet_pair(params, SecurityLevel::Standard);

    const HEADER_LEN: usize = 50;
    let message = b"Hello from WASM!";

    let mut packet = BytesMut::with_capacity(message.len() + HEADER_LEN);
    for x in 0..HEADER_LEN as u8 {
        packet.put_u8(x);
    }
    packet.put(&message[..]);

    let original = packet.clone();

    alice
        .protect_message_packet(Some(SecurityLevel::Standard), HEADER_LEN, &mut packet)
        .expect("encrypt");
    assert_ne!(packet, original, "ciphertext must differ from plaintext");

    let mut header = packet.split_to(HEADER_LEN);
    bob.validate_message_packet(Some(SecurityLevel::Standard), &header[..], &mut packet)
        .expect("decrypt");

    header.unsplit(packet);
    assert_eq!(header, original, "decrypted must match original");
}

/// Verify encrypt/decrypt with ChaCha20-Poly1305.
#[wasm_bindgen_test]
fn test_encrypt_decrypt_chacha() {
    let params = EncryptionAlgorithm::ChaCha20Poly_1305 + KemAlgorithm::MlKem;
    let (alice, bob) = create_ratchet_pair(params, SecurityLevel::Standard);

    const HEADER_LEN: usize = 50;
    let message = b"ChaCha20 on WASM works!";

    let mut packet = BytesMut::with_capacity(message.len() + HEADER_LEN);
    for x in 0..HEADER_LEN as u8 {
        packet.put_u8(x);
    }
    packet.put(&message[..]);

    let original = packet.clone();

    alice
        .protect_message_packet(Some(SecurityLevel::Standard), HEADER_LEN, &mut packet)
        .expect("encrypt chacha");

    let mut header = packet.split_to(HEADER_LEN);
    bob.validate_message_packet(Some(SecurityLevel::Standard), &header[..], &mut packet)
        .expect("decrypt chacha");

    header.unsplit(packet);
    assert_eq!(header, original);
}

/// Encrypt/decrypt with a larger payload to exercise chunked processing paths.
#[wasm_bindgen_test]
fn test_encrypt_decrypt_large_payload() {
    let params = EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem;
    let (alice, bob) = create_ratchet_pair(params, SecurityLevel::Standard);

    const HEADER_LEN: usize = 50;
    let message = vec![0xABu8; 8192];

    let mut packet = BytesMut::with_capacity(message.len() + HEADER_LEN);
    for x in 0..HEADER_LEN as u8 {
        packet.put_u8(x);
    }
    packet.put(&message[..]);

    let original = packet.clone();

    alice
        .protect_message_packet(Some(SecurityLevel::Standard), HEADER_LEN, &mut packet)
        .expect("encrypt large");

    let mut header = packet.split_to(HEADER_LEN);
    bob.validate_message_packet(Some(SecurityLevel::Standard), &header[..], &mut packet)
        .expect("decrypt large");

    header.unsplit(packet);
    assert_eq!(header, original);
}

/// Verify multiple sequential encrypt/decrypt operations (ratchet state advances).
#[wasm_bindgen_test]
fn test_multiple_messages() {
    let params = EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem;
    let (alice, bob) = create_ratchet_pair(params, SecurityLevel::Standard);

    const HEADER_LEN: usize = 50;

    for i in 0u8..10 {
        let message = format!("Message number {i}");
        let mut packet = BytesMut::with_capacity(message.len() + HEADER_LEN);
        for x in 0..HEADER_LEN as u8 {
            packet.put_u8(x);
        }
        packet.put(message.as_bytes());
        let original = packet.clone();

        alice
            .protect_message_packet(Some(SecurityLevel::Standard), HEADER_LEN, &mut packet)
            .expect("encrypt");

        let mut header = packet.split_to(HEADER_LEN);
        bob.validate_message_packet(Some(SecurityLevel::Standard), &header[..], &mut packet)
            .expect("decrypt");

        header.unsplit(packet);
        assert_eq!(header, original, "message {i} mismatch");
    }
}
