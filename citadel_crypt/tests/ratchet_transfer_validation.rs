//! A ratchet transfer's public nonces arrive from the counterpart, and every cipher reads a fixed
//! number of bytes from them. Bob refuses a transfer whose nonce does not have the length its
//! algorithm uses, for both ratchet kinds, instead of failing later when he encrypts.
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::mono::{MonoAliceToBobTransfer, MonoRatchet};
use citadel_crypt::ratchets::stacked::constructor::AliceToBobTransfer;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::EncryptionAlgorithmExt;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

const PSKS: &[&[u8]] = &[b"psk"];

fn suites() -> [CryptoParameters; 2] {
    [
        KemAlgorithm::MlKem768Fips203 + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem768Fips203
            + EncryptionAlgorithm::MlKemHybrid
            + citadel_types::crypto::SigAlgorithm::MlDsa65,
    ]
}

/// Replaces the nonce that ends `tail` bytes before the end of `bytes` with one of `len` bytes.
fn with_nonce(bytes: &[u8], nonce_len: usize, tail: usize, len: usize) -> Vec<u8> {
    let end = bytes.len() - tail;
    let start = end - nonce_len - 8;
    assert_eq!(
        bytes[start..start + 8],
        (nonce_len as u64).to_le_bytes(),
        "the nonce's length prefix sits where expected"
    );
    let mut forged = bytes[..start].to_vec();
    forged.extend_from_slice(&(len as u64).to_le_bytes());
    forged.extend(std::iter::repeat_n(0u8, len));
    forged.extend_from_slice(&bytes[end..]);
    forged
}

fn stacked_bob_accepts(params: CryptoParameters, nonce_len: Option<usize>) -> bool {
    type C = <StackedRatchet as Ratchet>::Constructor;
    let opts = ConstructorOpts::new_vec_init(params, SecurityLevel::Standard);
    let alice = C::new_alice(opts.clone(), 7, 0).unwrap();
    let mut bytes = bincode::serialize(&alice.stage0_alice().unwrap()).unwrap();
    if let Some(len) = nonce_len {
        // msg_nonce is followed by the security level (4), the cid (8) and the version (4).
        bytes = with_nonce(&bytes, params.encryption_algorithm.nonce_len(), 16, len);
    }
    let transfer: AliceToBobTransfer = citadel_io::decode::deserialize(&bytes).unwrap();
    C::new_bob(7, opts, transfer, PSKS).is_some()
}

fn mono_bob_accepts(params: CryptoParameters, nonce_len: Option<usize>) -> bool {
    type C = <MonoRatchet as Ratchet>::Constructor;
    let opts = vec![ConstructorOpts::new_init(params)];
    let alice = C::new_alice(opts.clone(), 7, 0).unwrap();
    let mut bytes = bincode::serialize(&alice.stage0_alice().unwrap()).unwrap();
    if let Some(len) = nonce_len {
        // The nonce is followed by the cid (8) and the version (4).
        bytes = with_nonce(&bytes, params.encryption_algorithm.nonce_len(), 12, len);
    }
    let transfer: MonoAliceToBobTransfer = citadel_io::decode::deserialize(&bytes).unwrap();
    <C as EndpointRatchetConstructor<MonoRatchet>>::new_bob(7, opts, transfer, PSKS).is_some()
}

#[test]
fn a_transfer_with_the_algorithms_nonce_length_is_accepted() {
    for params in suites() {
        assert!(stacked_bob_accepts(params, None), "{params:?}");
        assert!(mono_bob_accepts(params, None), "{params:?}");
    }
}

#[test]
fn a_transfer_with_a_short_nonce_is_refused() {
    for params in suites() {
        for len in [0, 4] {
            assert!(!stacked_bob_accepts(params, Some(len)), "{params:?} {len}");
            assert!(!mono_bob_accepts(params, Some(len)), "{params:?} {len}");
        }
    }
}

#[test]
fn a_transfer_with_a_long_nonce_is_refused() {
    let params = KemAlgorithm::MlKem768Fips203 + EncryptionAlgorithm::AES_GCM_256;
    assert!(!stacked_bob_accepts(params, Some(32)));
    assert!(!mono_bob_accepts(params, Some(32)));
}
