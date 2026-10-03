use super::*;

const ALGS: [KemAlgorithm; 2] = [
    KemAlgorithm::MlKem768Fips203,
    KemAlgorithm::MlKem1024Fips203,
];

#[test]
fn kem_round_trip() {
    for alg in ALGS {
        let (pk, sk) = keypair(alg).unwrap();
        let (ct, ss_a) = encapsulate(alg, &pk).unwrap();
        let ss_b = decapsulate(alg, &ct, &sk).unwrap();
        assert_eq!(ss_a, ss_b, "{alg:?} shared secrets differ");
        assert_eq!(ss_a.len(), 32, "{alg:?} shared secret is not 32 bytes");
        assert_eq!(ct.len(), ciphertext_len(alg).unwrap());
    }
}

#[test]
fn keygen_is_deterministic_from_seed() {
    let seed = [7u8; 64];
    for alg in ALGS {
        let (pk1, sk1) = keypair_from_seed(alg, &seed).unwrap();
        let (pk2, sk2) = keypair_from_seed(alg, &seed).unwrap();
        assert_eq!(pk1, pk2, "{alg:?} public key is not seed-deterministic");
        assert_eq!(sk1, sk2, "{alg:?} secret key is not seed-deterministic");
    }
}

#[test]
fn key_lengths_match_fips203() {
    let (pk, sk) = keypair(KemAlgorithm::MlKem768Fips203).unwrap();
    assert_eq!(pk.len(), sizes::PK_768);
    assert_eq!(sk.len(), sizes::SK_768);
    let (pk, sk) = keypair(KemAlgorithm::MlKem1024Fips203).unwrap();
    assert_eq!(pk.len(), sizes::PK_1024);
    assert_eq!(sk.len(), sizes::SK_1024);
}

#[test]
fn pke_round_trip_arbitrary_lengths() {
    for alg in ALGS {
        let (pk, sk) = keypair(alg).unwrap();
        for len in [0usize, 1, 31, 32, 33, 4096] {
            let msg = vec![0xABu8; len];
            let nonce = b"associated-nonce";
            let ct = encrypt_pke(alg, &pk, &msg, nonce).unwrap();
            let out = decrypt_pke(alg, &sk, &ct).unwrap();
            assert_eq!(out, msg, "{alg:?} PKE round-trip failed at len {len}");
        }
    }
}

#[test]
fn pke_rejects_tampered_ciphertext() {
    let alg = KemAlgorithm::MlKem768Fips203;
    let (pk, sk) = keypair(alg).unwrap();
    let mut ct = encrypt_pke(alg, &pk, b"secret", b"nonce").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(decrypt_pke(alg, &sk, &ct).is_err());
}

#[test]
fn legacy_variant_is_rejected() {
    assert!(keypair(KemAlgorithm::MlKem).is_err());
    assert!(ciphertext_len(KemAlgorithm::MlKem).is_err());
}

#[test]
fn public_key_validation_accepts_real_keys_and_refuses_bad_ones() {
    for alg in ALGS {
        let (pk, _) = keypair(alg).unwrap();
        assert!(public_key_is_valid(alg, &pk), "{alg:?} refused its own key");
        assert!(
            !public_key_is_valid(alg, &pk[1..]),
            "{alg:?} accepted a short key"
        );
        // Every coefficient is 12 bits; 0xFFF exceeds q = 3329, so this key is not reduced.
        let mut unreduced = pk.clone();
        unreduced[0] = 0xFF;
        unreduced[1] |= 0x0F;
        assert!(
            !public_key_is_valid(alg, &unreduced),
            "{alg:?} accepted an unreduced key"
        );
    }
    assert!(!public_key_is_valid(KemAlgorithm::MlKem, &[0u8; 1568]));
}
