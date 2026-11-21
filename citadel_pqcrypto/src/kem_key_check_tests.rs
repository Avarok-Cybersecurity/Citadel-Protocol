use super::*;

use citadel_types::crypto::AlgorithmsExt;

/// The ML-KEM modulus (FIPS 203); every encoded coefficient must be below it.
const Q: u16 = 3329;

fn all() -> Vec<KemAlgorithm> {
    KemAlgorithm::list()
}

fn honest_public_key(alg: KemAlgorithm) -> Vec<u8> {
    crate::libcrux_kem::keypair(alg).unwrap().0
}

/// Sets the first coefficient to q, the smallest unreduced value.
fn with_unreduced_coefficient(mut key: Vec<u8>) -> Vec<u8> {
    key[0] = (Q & 0xff) as u8;
    key[1] = (key[1] & 0xf0) | (Q >> 8) as u8;
    key
}

#[test]
fn honest_keys_pass_for_every_suite() {
    for alg in all() {
        for _ in 0..500 {
            assert!(public_key_is_valid(alg, &honest_public_key(alg)), "{alg:?}");
        }
    }
}

#[test]
fn derived_keys_pass_for_every_suite() {
    for alg in all() {
        for i in 0..500u32 {
            let mut seed = [0u8; 64];
            seed[..4].copy_from_slice(&i.to_be_bytes());
            let (public, _) = crate::kem_keypair_from_seed(alg, &seed).unwrap();
            assert!(public_key_is_valid(alg, &public), "{alg:?}");
        }
    }
}

#[test]
fn a_key_with_an_unreduced_coefficient_fails_for_every_suite() {
    for alg in all() {
        let key = with_unreduced_coefficient(honest_public_key(alg));
        assert!(!public_key_is_valid(alg, &key), "{alg:?}");
    }
}

#[test]
fn a_key_of_the_wrong_length_fails_for_every_suite() {
    for alg in all() {
        let mut key = honest_public_key(alg);
        key.pop();
        assert!(!public_key_is_valid(alg, &key), "{alg:?}");
    }
}

#[test]
fn nothing_is_encapsulated_or_encrypted_to_an_invalid_key() {
    use crate::encryption::kyber_module::encrypt_pke;
    for alg in all() {
        let key = with_unreduced_coefficient(honest_public_key(alg));
        assert!(
            encrypt_pke(alg, &key, [7u8; 32], [0u8; 32]).is_err(),
            "{alg:?} pke"
        );
        assert!(
            crate::libcrux_kem::encapsulate(alg, &key).is_err(),
            "{alg:?} kem"
        );
        let key = with_unreduced_coefficient(honest_public_key(alg));
        assert!(
            crate::kem_encapsulate(alg, &key).is_err(),
            "{alg:?} tree kem"
        );
    }
}

#[test]
fn bob_refuses_an_invalid_key_from_alice() {
    use crate::constructor_opts::ConstructorOpts;
    use crate::wire::AliceToBobTransferParameters;
    use crate::PostQuantumContainer;
    for alg in all() {
        let params = alg + citadel_types::crypto::EncryptionAlgorithm::AES_GCM_256;
        let opts = ConstructorOpts::new_init(params);
        let alice = PostQuantumContainer::new_alice(opts.clone()).unwrap();
        let mut transfer = alice.generate_alice_to_bob_transfer().unwrap();
        let AliceToBobTransferParameters::PureSymmetric { alice_pk, .. } = &mut transfer else {
            panic!("an unsigned suite sends an unsigned transfer");
        };
        *alice_pk = std::sync::Arc::new(with_unreduced_coefficient(alice_pk.to_vec()).into());
        assert!(
            PostQuantumContainer::new_bob(opts, transfer, &[b"psk"]).is_err(),
            "{alg:?}"
        );
    }
}
