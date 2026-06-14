//! Per-message AEAD keying for pipelined PFS (`docs/pfs-symmetric-ratchet-design.md`, step 2).
//!
//! The standard path keys an `AeadModule` once from the ratchet-version KEM secret and reuses it for
//! every message in that version (different nonce only). For the pipelined-PFS mode, each message
//! instead gets its own forward-secure key `MK_i` from the symmetric ratchet chain
//! (`citadel_crypt::ratchets::message_chain`). These stateless helpers seal/open a single message by
//! constructing a fresh cipher from `MK_i` — re-keying the AEAD per message.
//!
//! Supported for the plain symmetric ciphers only (AES-256-GCM, ChaCha20-Poly1305, Ascon-80pq).
//! `MlKemHybrid` (the per-message-asymmetric `KyberModule`) is intentionally rejected — pipelining it
//! is a separate effort; selecting `PerfectPipelined` with MlKemHybrid must fall back to per-message KEM.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, Buffer};
use aes_gcm::KeyInit;
use citadel_types::crypto::{
    EncryptionAlgorithm, AES_GCM_NONCE_LENGTH_BYTES, ASCON_NONCE_LENGTH_BYTES,
    CHA_CHA_NONCE_LENGTH_BYTES,
};
use citadel_types::errors::Error;

/// AES/ChaCha symmetric-key length (bytes).
const SYM_KEY_LEN: usize = 32;
/// Ascon-80pq key length (bytes).
const ASCON_KEY_LEN: usize = 20;

fn require<'a>(buf: &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8], Error> {
    if buf.len() >= n {
        Ok(&buf[..n])
    } else {
        Err(Error::Generic(what))
    }
}

/// Seal `buf` in place (append tag) under a fresh cipher keyed by `key` (`MK_i`). `nonce` must be at
/// least the cipher's nonce length; `ad` is authenticated, not encrypted.
pub fn seal_in_place_with_key(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    buf: &mut dyn Buffer,
) -> Result<(), Error> {
    match algorithm {
        EncryptionAlgorithm::AES_GCM_256 => {
            let cipher =
                aes_gcm::Aes256Gcm::new_from_slice(require(key, SYM_KEY_LEN, "AES key too short")?)
                    .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .encrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        AES_GCM_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::ChaCha20Poly_1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(require(
                key,
                SYM_KEY_LEN,
                "ChaCha key too short",
            )?)
            .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .encrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        CHA_CHA_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::Ascon80pq => {
            let cipher = ascon_aead::Ascon80pq::new_from_slice(require(
                key,
                ASCON_KEY_LEN,
                "Ascon key too short",
            )?)
            .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .encrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        ASCON_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::MlKemHybrid => Err(Error::Generic(
            "pipelined PFS (per-message key) is not supported for MlKemHybrid",
        )),
    }
}

/// Open `buf` in place (verify + strip tag) under a fresh cipher keyed by `key` (`MK_i`). Mirrors
/// [`seal_in_place_with_key`].
pub fn open_in_place_with_key(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    buf: &mut dyn Buffer,
) -> Result<(), Error> {
    match algorithm {
        EncryptionAlgorithm::AES_GCM_256 => {
            let cipher =
                aes_gcm::Aes256Gcm::new_from_slice(require(key, SYM_KEY_LEN, "AES key too short")?)
                    .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .decrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        AES_GCM_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::ChaCha20Poly_1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(require(
                key,
                SYM_KEY_LEN,
                "ChaCha key too short",
            )?)
            .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .decrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        CHA_CHA_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::Ascon80pq => {
            let cipher = ascon_aead::Ascon80pq::new_from_slice(require(
                key,
                ASCON_KEY_LEN,
                "Ascon key too short",
            )?)
            .map_err(|_| Error::EncryptionFailure)?;
            cipher
                .decrypt_in_place(
                    GenericArray::from_slice(require(
                        nonce,
                        ASCON_NONCE_LENGTH_BYTES,
                        "nonce too short",
                    )?),
                    ad,
                    buf,
                )
                .map_err(|_| Error::EncryptionFailure)
        }
        EncryptionAlgorithm::MlKemHybrid => Err(Error::Generic(
            "pipelined PFS (per-message key) is not supported for MlKemHybrid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(alg: EncryptionAlgorithm) {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let ad = b"associated-data";
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();

        let mut buf = plaintext.clone();
        seal_in_place_with_key(alg, &key, &nonce, ad, &mut buf).unwrap();
        assert_ne!(buf, plaintext, "{alg:?}: ciphertext == plaintext");
        open_in_place_with_key(alg, &key, &nonce, ad, &mut buf).unwrap();
        assert_eq!(buf, plaintext, "{alg:?}: roundtrip mismatch");
    }

    #[test]
    fn roundtrip_all_symmetric_ciphers() {
        roundtrip(EncryptionAlgorithm::AES_GCM_256);
        roundtrip(EncryptionAlgorithm::ChaCha20Poly_1305);
        roundtrip(EncryptionAlgorithm::Ascon80pq);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let nonce = [0x22u8; 16];
        let ad = b"";
        let mut buf = b"secret".to_vec();
        seal_in_place_with_key(
            EncryptionAlgorithm::AES_GCM_256,
            &[1u8; 32],
            &nonce,
            ad,
            &mut buf,
        )
        .unwrap();
        // A different per-message key must not authenticate.
        assert!(open_in_place_with_key(
            EncryptionAlgorithm::AES_GCM_256,
            &[2u8; 32],
            &nonce,
            ad,
            &mut buf
        )
        .is_err());
    }

    #[test]
    fn distinct_keys_give_distinct_ciphertexts() {
        let nonce = [0x22u8; 16];
        let (mut a, mut b) = (b"msg".to_vec(), b"msg".to_vec());
        seal_in_place_with_key(
            EncryptionAlgorithm::ChaCha20Poly_1305,
            &[1u8; 32],
            &nonce,
            b"",
            &mut a,
        )
        .unwrap();
        seal_in_place_with_key(
            EncryptionAlgorithm::ChaCha20Poly_1305,
            &[2u8; 32],
            &nonce,
            b"",
            &mut b,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn mlkem_hybrid_is_rejected() {
        let mut buf = b"x".to_vec();
        assert!(seal_in_place_with_key(
            EncryptionAlgorithm::MlKemHybrid,
            &[0u8; 32],
            &[0u8; 16],
            b"",
            &mut buf
        )
        .is_err());
    }
}
