//! The hybrid scheme's declared ciphertext length bounds the length it produces, tightly, for every
//! KEM and signature scheme a session can name.

use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::{EncryptionAlgorithmExt, PostQuantumContainer};
use citadel_types::crypto::{AlgorithmsExt, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm};

const PSKS: &[&[u8]] = &[b"psk"];
/// The hybrid scheme pads its body to this block, so its real length sits below the bound by less.
const SCRAMBLE_BLOCK: usize = 32;

fn pair(kem: KemAlgorithm, sig: SigAlgorithm) -> (PostQuantumContainer, PostQuantumContainer) {
    let params = kem + EncryptionAlgorithm::MlKemHybrid + sig;
    let mut alice = PostQuantumContainer::new_alice(ConstructorOpts::new_init(params)).unwrap();
    let to_bob = alice.generate_alice_to_bob_transfer().unwrap();
    let bob =
        PostQuantumContainer::new_bob(ConstructorOpts::new_init(params), to_bob, PSKS).unwrap();
    let to_alice = bob.generate_bob_to_alice_transfer().unwrap();
    alice.alice_on_receive_ciphertext(to_alice, PSKS).unwrap();
    (alice, bob)
}

#[test]
fn hybrid_ciphertexts_have_the_declared_length_for_each_kem() {
    let nonce = vec![7u8; EncryptionAlgorithm::MlKemHybrid.nonce_len()];
    for kem in KemAlgorithm::list() {
        for sig in [SigAlgorithm::MlDsa65, SigAlgorithm::FnDsa512] {
            let (alice, bob) = pair(kem, sig);
            let mut tightest = usize::MAX;
            for len in (0..=96).chain([479, 480, 481, 4096]) {
                let plaintext = vec![0xA5u8; len];
                let ciphertext = alice.encrypt(&plaintext, &nonce).unwrap();
                let declared = EncryptionAlgorithm::MlKemHybrid.max_ciphertext_len(len, kem, sig);
                assert!(
                    ciphertext.len() <= declared && declared - ciphertext.len() < SCRAMBLE_BLOCK,
                    "{kem:?} {sig:?} plaintext of {len} bytes: {} bytes, declared {declared}",
                    ciphertext.len()
                );
                tightest = tightest.min(declared - ciphertext.len());
                let mut received = ciphertext;
                assert_eq!(bob.decrypt(&mut received[..], &nonce).unwrap(), plaintext);
            }
            assert_eq!(
                tightest, 0,
                "{kem:?} {sig:?}: the bound is reached at some length"
            );
        }
    }
}
