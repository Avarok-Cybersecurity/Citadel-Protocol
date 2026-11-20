//! A key-exchange transfer received from the counterpart is checked against the parameters it is
//! used with before any of its fields are trusted, and a nonce of the wrong length is refused by
//! every cipher: each case returns an error and never panics.
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PSKS: &[&[u8]] = &[b"psk"];

fn pair(params: CryptoParameters) -> (PostQuantumContainer, PostQuantumContainer) {
    let mut alice = PostQuantumContainer::new_alice(ConstructorOpts::new_init(params)).unwrap();
    let tx = alice.generate_alice_to_bob_transfer().unwrap();
    let bob = PostQuantumContainer::new_bob(ConstructorOpts::new_init(params), tx, PSKS).unwrap();
    alice
        .alice_on_receive_ciphertext(bob.generate_bob_to_alice_transfer().unwrap(), PSKS)
        .unwrap();
    (alice, bob)
}

/// Alice built with `alice_params` sends her transfer to a Bob built with `bob_params`.
fn bob_receives(alice_params: CryptoParameters, bob_params: CryptoParameters) -> bool {
    citadel_types::utils::validate_crypto_params(&bob_params).expect("Bob's params are valid");
    let alice = PostQuantumContainer::new_alice(ConstructorOpts::new_init(alice_params)).unwrap();
    let tx = alice.generate_alice_to_bob_transfer().unwrap();
    catch_unwind(AssertUnwindSafe(|| {
        PostQuantumContainer::new_bob(ConstructorOpts::new_init(bob_params), tx, PSKS).is_err()
    }))
    .expect("constructing Bob panicked")
}

#[test]
fn an_unsigned_transfer_is_refused_by_a_signing_bob() {
    assert!(bob_receives(
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
    ));
}

#[test]
fn a_signed_transfer_is_refused_by_a_bob_that_does_not_sign() {
    assert!(bob_receives(
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256 + SigAlgorithm::MlDsa65,
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
    ));
}

#[test]
fn a_transfer_naming_another_signature_scheme_is_refused() {
    assert!(bob_receives(
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::FnDsa512,
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
    ));
}

#[test]
fn a_transfer_naming_another_kem_is_refused() {
    assert!(bob_receives(
        KemAlgorithm::MlKem1024Fips203 + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
    ));
}

#[test]
fn a_matching_transfer_is_accepted() {
    assert!(!bob_receives(
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
    ));
}

/// Alice built with `alice_params` receives the reply of a Bob built with `bob_params`.
fn alice_refuses_reply(alice_params: CryptoParameters, bob_params: CryptoParameters) -> bool {
    let mut alice =
        PostQuantumContainer::new_alice(ConstructorOpts::new_init(alice_params)).unwrap();
    let other_alice =
        PostQuantumContainer::new_alice(ConstructorOpts::new_init(bob_params)).unwrap();
    let bob = PostQuantumContainer::new_bob(
        ConstructorOpts::new_init(bob_params),
        other_alice.generate_alice_to_bob_transfer().unwrap(),
        PSKS,
    )
    .unwrap();
    let reply = bob.generate_bob_to_alice_transfer().unwrap();
    catch_unwind(AssertUnwindSafe(|| {
        alice.alice_on_receive_ciphertext(reply, PSKS).is_err()
    }))
    .expect("receiving the reply panicked")
}

#[test]
fn an_unsigned_reply_is_refused_by_a_signing_alice() {
    assert!(alice_refuses_reply(
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
    ));
}

#[test]
fn a_signed_reply_is_refused_by_an_alice_that_does_not_sign() {
    assert!(alice_refuses_reply(
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256 + SigAlgorithm::MlDsa65,
    ));
}

fn short_nonce_is_refused(params: CryptoParameters) {
    let (alice, bob) = pair(params);
    for len in [0usize, 4, 11] {
        let nonce = vec![0u8; len];
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            (
                alice.encrypt(b"x", &nonce).is_err(),
                bob.decrypt(vec![0u8; 64], &nonce).is_err(),
                alice.local_encrypt(b"x", &nonce).is_err(),
            )
        }))
        .unwrap_or_else(|_| panic!("a {len}-byte nonce panicked under {params:?}"));
        assert_eq!(
            outcome,
            (true, true, true),
            "a {len}-byte nonce under {params:?}"
        );
    }
}

#[test]
fn a_short_nonce_is_refused_by_the_plain_ciphers() {
    for enx in [
        EncryptionAlgorithm::AES_GCM_256,
        EncryptionAlgorithm::ChaCha20Poly_1305,
        EncryptionAlgorithm::Ascon80pq,
    ] {
        short_nonce_is_refused(KemAlgorithm::MlKem + enx);
    }
}

#[test]
fn a_short_nonce_is_refused_by_the_hybrid_cipher() {
    short_nonce_is_refused(
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
    );
}
