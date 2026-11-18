//! The hybrid scheme's decryption runs only after the counterpart's signature verifies, so a peer
//! that holds valid signing keys controls every byte it reaches. This drives arbitrary bytes into
//! that post-signature path directly: they must be refused without panicking. The path's trailing
//! checksum is unkeyed, so each input is given a valid one, and the mutations reach the length
//! fields, the sealed dictionary and the scrambled body behind it.

#[path = "../tests/support/wire_fuzz.rs"]
mod wire_fuzz;

use crate::encryption::aes_impl::AesModule;
use crate::encryption::kyber_module::{core_kyber_otp_decrypt, core_kyber_otp_encrypt};
use crate::PostQuantumMetaKex;
use aes_gcm::KeyInit;
use citadel_types::crypto::KemAlgorithm;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn bytes_past_the_signature_check_never_panic() {
    let keypair = kyber_pke::kem_keypair().unwrap();
    let public_key = keypair.public.to_vec();
    let secret_key = keypair.secret.to_vec();
    let cipher = || AesModule {
        aead: aes_gcm::Aes256Gcm::new(&[3u8; 32].into()),
        kex: PostQuantumMetaKex {
            remote_public_key: None,
            public_key: Arc::new(public_key.clone().into()),
            secret_key: None,
            ciphertext: None,
            shared_secret: None,
            kem_alg: KemAlgorithm::MlKem,
        },
    };
    let nonce = [9u8; 32];
    let seeds = [0usize, 1, 31, 32, 33, 200]
        .iter()
        .map(|&len| {
            let mut buf = vec![5u8; len];
            core_kyber_otp_encrypt(
                &cipher(),
                &public_key,
                KemAlgorithm::MlKem,
                &nonce,
                b"ad",
                &mut buf,
            )
            .unwrap();
            let mut check = buf.clone();
            core_kyber_otp_decrypt(
                &cipher(),
                &secret_key,
                KemAlgorithm::MlKem,
                &nonce,
                b"ad",
                &mut check,
            )
            .expect("a genuine seed decrypts");
            buf.truncate(buf.len() - 32);
            buf
        })
        .collect();
    let aes = cipher();
    wire_fuzz::campaign(
        "hybrid core",
        seeds,
        2_000,
        Duration::from_secs(300),
        move |bytes| {
            use sha3::Digest;
            let mut buf = bytes.to_vec();
            buf.extend_from_slice(&sha3::Sha3_256::digest(bytes));
            let _ = core_kyber_otp_decrypt(
                &aes,
                &secret_key,
                KemAlgorithm::MlKem,
                &nonce,
                b"ad",
                &mut buf,
            );
        },
    );
}
