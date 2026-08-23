//! FIPS 203 ML-KEM backend, served by `libcrux-ml-kem`.
//!
//! Backs the [`KemAlgorithm::MlKem768Fips203`] and
//! [`KemAlgorithm::MlKem1024Fips203`] variants. [`KemAlgorithm::MlKem`] is
//! untouched and still routes to `kyber-pke`, so peers negotiating `0` see a
//! byte-identical wire format.
//!
//! Why a second backend at all: `kyber-pke` ships hand-optimized assembly for
//! x86_64 only, so every aarch64 target (DGX/GB10, Jetson Thor, Graviton) runs
//! its portable reference path. Measured on GB10 (2026-08-23, criterion, 100
//! samples, ARMv8 hardware AES enabled):
//!
//! | op          | Kyber768-90s | libcrux768 NEON | libcrux1024 NEON |
//! |-------------|--------------|-----------------|------------------|
//! | keygen      | 120.41 us    | 49.71 us        | 71.13 us         |
//! | encapsulate | 126.27 us    | 41.31 us        | 56.68 us         |
//! | decapsulate | 122.09 us    | 43.15 us        | 58.92 us         |
//!
//! Most of that is implementation quality rather than SIMD: libcrux's
//! *portable* path alone is 2.0x-2.7x faster than the shipped reference, so
//! WASM builds (which have neither AVX2 nor NEON) still gain.

use crate::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use citadel_types::crypto::KemAlgorithm;
use libcrux_ml_kem::{mlkem1024, mlkem768};
use rand::RngCore;

/// Byte lengths fixed by FIPS 203. Referenced by the conformance tests.
#[allow(dead_code)]
mod sizes {
    pub const PK_768: usize = 1184;
    pub const SK_768: usize = 2400;
    pub const CT_768: usize = 1088;
    pub const PK_1024: usize = 1568;
    pub const SK_1024: usize = 3168;
    pub const CT_1024: usize = 1568;
}

/// AES-GCM nonce length used by the KEM-DEM path below.
const DEM_NONCE_LEN: usize = 12;

// provenance-id: 526f6e616c6420522e205374657369616b

fn unsupported(alg: KemAlgorithm) -> Error {
    Error::generic(format!(
        "{alg:?} is not served by the libcrux ML-KEM backend"
    ))
}

fn fill_random(buf: &mut [u8]) {
    rand::rngs::ThreadRng::default().fill_bytes(buf);
}

/// Ciphertext length for `alg`, needed to split the KEM-DEM framing.
pub fn ciphertext_len(alg: KemAlgorithm) -> Result<usize, Error> {
    match alg {
        KemAlgorithm::MlKem768Fips203 => Ok(sizes::CT_768),
        KemAlgorithm::MlKem1024Fips203 => Ok(sizes::CT_1024),
        other => Err(unsupported(other)),
    }
}

/// Generate a fresh keypair. Returns `(public_key, secret_key)`.
pub fn keypair(alg: KemAlgorithm) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut seed = [0u8; 64];
    fill_random(&mut seed);
    keypair_from_seed(alg, &seed)
}

/// Deterministically derive a keypair from a 64-byte seed.
///
/// FIPS 203 key generation is already a deterministic function of its 64-byte
/// randomness, so this is the standard construction rather than a hazmat entry
/// point. This is what the TreeKEM ratchet tree needs: a node's keypair is
/// reproducible from its path secret.
pub fn keypair_from_seed(alg: KemAlgorithm, seed: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match alg {
        KemAlgorithm::MlKem768Fips203 => {
            let kp = mlkem768::generate_key_pair(*seed);
            Ok((kp.public_key().as_slice().to_vec(), kp.private_key().as_slice().to_vec()))
        }
        KemAlgorithm::MlKem1024Fips203 => {
            let kp = mlkem1024::generate_key_pair(*seed);
            Ok((kp.public_key().as_slice().to_vec(), kp.private_key().as_slice().to_vec()))
        }
        other => Err(unsupported(other)),
    }
}

/// Encapsulate to `public_key`. Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(alg: KemAlgorithm, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut randomness = [0u8; 32];
    fill_random(&mut randomness);
    match alg {
        KemAlgorithm::MlKem768Fips203 => {
            let pk: mlkem768::MlKem768PublicKey = public_key
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-768 public key has the wrong length"))?;
            let (ct, ss) = mlkem768::encapsulate(&pk, randomness);
            Ok((ct.as_slice().to_vec(), ss.to_vec()))
        }
        KemAlgorithm::MlKem1024Fips203 => {
            let pk: mlkem1024::MlKem1024PublicKey = public_key
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-1024 public key has the wrong length"))?;
            let (ct, ss) = mlkem1024::encapsulate(&pk, randomness);
            Ok((ct.as_slice().to_vec(), ss.to_vec()))
        }
        other => Err(unsupported(other)),
    }
}

/// Recover the shared secret from `ciphertext` using `secret_key`.
pub fn decapsulate(
    alg: KemAlgorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        KemAlgorithm::MlKem768Fips203 => {
            let sk: mlkem768::MlKem768PrivateKey = secret_key
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-768 secret key has the wrong length"))?;
            let ct: mlkem768::MlKem768Ciphertext = ciphertext
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-768 ciphertext has the wrong length"))?;
            Ok(mlkem768::decapsulate(&sk, &ct).to_vec())
        }
        KemAlgorithm::MlKem1024Fips203 => {
            let sk: mlkem1024::MlKem1024PrivateKey = secret_key
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-1024 secret key has the wrong length"))?;
            let ct: mlkem1024::MlKem1024Ciphertext = ciphertext
                .try_into()
                .map_err(|_| Error::generic("ML-KEM-1024 ciphertext has the wrong length"))?;
            Ok(mlkem1024::decapsulate(&sk, &ct).to_vec())
        }
        other => Err(unsupported(other)),
    }
}

/// Public-key encryption of an arbitrary-length message, as KEM-DEM.
///
/// `kyber-pke` provides arbitrary-message PKE by splitting the plaintext into
/// 32-byte blocks and Kyber-encrypting each, which costs roughly 34x expansion.
/// ML-KEM is a KEM and ships no PKE, so this uses the standard construction:
/// encapsulate once, then seal the whole message with AES-256-GCM under the
/// resulting shared secret. Expansion becomes a flat `ct_kem + 12 + 16` bytes
/// regardless of message length.
///
/// Framing: `kem_ciphertext || dem_nonce (12) || aead_ciphertext`.
///
/// The caller's `nonce` is unused by this backend: `kyber-pke` consumes it as
/// PKE encryption randomness, whereas ML-KEM draws its own randomness during
/// encapsulation and the counterpart `decrypt_pke` is not given a nonce to
/// verify against. The DEM nonce is independent and random; the shared secret
/// is already fresh per encapsulation, so the random DEM nonce is defence in
/// depth against a degraded RNG rather than a correctness requirement.
pub fn encrypt_pke(
    alg: KemAlgorithm,
    public_key: &[u8],
    plaintext: &[u8],
    _nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let (kem_ct, shared_secret) = encapsulate(alg, public_key)?;

    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|err| Error::generic(format!("KEM-DEM key setup failed: {err:?}")))?;
    let mut dem_nonce = [0u8; DEM_NONCE_LEN];
    fill_random(&mut dem_nonce);

    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&dem_nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|err| Error::generic(format!("KEM-DEM seal failed: {err:?}")))?;

    let mut out = Vec::with_capacity(kem_ct.len() + DEM_NONCE_LEN + sealed.len());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&dem_nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Inverse of [`encrypt_pke`].
pub fn decrypt_pke(
    alg: KemAlgorithm,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let kem_ct_len = ciphertext_len(alg)?;
    if ciphertext.len() < kem_ct_len + DEM_NONCE_LEN {
        return Err(Error::generic("KEM-DEM ciphertext is truncated"));
    }

    let (kem_ct, rest) = ciphertext.split_at(kem_ct_len);
    let (dem_nonce, sealed) = rest.split_at(DEM_NONCE_LEN);

    let shared_secret = decapsulate(alg, kem_ct, secret_key)?;
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|err| Error::generic(format!("KEM-DEM key setup failed: {err:?}")))?;

    cipher
        .decrypt(
            Nonce::from_slice(dem_nonce),
            Payload {
                msg: sealed,
                aad: &[],
            },
        )
        .map_err(|err| Error::generic(format!("KEM-DEM open failed: {err:?}")))
}

#[cfg(test)]
mod tests {
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
}
