//! Checks applied to values received from the counterpart of a key exchange before any of them is
//! trusted: the kind and schemes of a transfer against the parameters it is used with, and the
//! shape of a public-key ciphertext against what its scheme produces.

use crate::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use citadel_types::crypto::{CryptoParameters, KemAlgorithm, SigAlgorithm};
use citadel_types::errors::Error;

fn mismatch(what: String) -> Error {
    citadel_io::error!(citadel_io::ErrorCode::KeyTransferMismatch, what)
}

/// Bob's side: Alice's transfer must name the KEM and signature scheme Bob is configured with, and
/// carry a signed public key exactly when that signature scheme is not [`SigAlgorithm::None`].
pub(crate) fn check_alice_transfer(
    params: &CryptoParameters,
    transfer: &AliceToBobTransferParameters,
) -> Result<(), Error> {
    let (kem, sig) = match transfer {
        AliceToBobTransferParameters::MixedAsymmetric {
            kem_scheme,
            sig_scheme,
            ..
        } => {
            if *sig_scheme == SigAlgorithm::None {
                return Err(mismatch(
                    "a signed transfer names no signature scheme".to_string(),
                ));
            }
            (*kem_scheme, *sig_scheme)
        }
        AliceToBobTransferParameters::PureSymmetric { kem_scheme, .. } => {
            (*kem_scheme, SigAlgorithm::None)
        }
    };
    if kem != params.kem_algorithm {
        return Err(mismatch(format!(
            "KEM {kem:?} where {:?} is configured",
            params.kem_algorithm
        )));
    }
    if sig != params.sig_algorithm {
        return Err(mismatch(format!(
            "signature scheme {sig:?} where {:?} is configured",
            params.sig_algorithm
        )));
    }
    Ok(())
}

/// Alice's side: Bob's reply must be signed exactly when Alice's own exchange is.
pub(crate) fn check_bob_transfer(
    alice_signs: bool,
    transfer: &BobToAliceTransferParameters,
) -> Result<(), Error> {
    let bob_signs = matches!(
        transfer,
        BobToAliceTransferParameters::MixedAsymmetric { .. }
    );
    if bob_signs != alice_signs {
        return Err(mismatch(format!(
            "a {} reply to a {} exchange",
            if bob_signs { "signed" } else { "unsigned" },
            if alice_signs { "signed" } else { "unsigned" }
        )));
    }
    Ok(())
}

/// A public-key ciphertext must have exactly the length `kem_alg` produces for a plaintext of
/// `plaintext_len` bytes, and (for the block-wise scheme) declare that same plaintext length, so the
/// decryptor never sizes a buffer or a block from a value it was sent.
pub(crate) fn check_pke_ciphertext(
    kem_alg: KemAlgorithm,
    ciphertext: &[u8],
    plaintext_len: usize,
) -> Result<(), Error> {
    let well_formed = match kem_alg {
        KemAlgorithm::MlKem => {
            ciphertext.len() == kyber_pke::ct_len(plaintext_len)
                && kyber_pke::plaintext_len(ciphertext) == Some(plaintext_len)
        }
        // The KEM-DEM backend frames its own ciphertext and checks every length before use.
        KemAlgorithm::MlKem768Fips203 | KemAlgorithm::MlKem1024Fips203 => true,
    };
    if well_formed {
        Ok(())
    } else {
        Err(citadel_io::error!(
            citadel_io::ErrorCode::PkeCiphertextMalformed,
            ciphertext.len()
        ))
    }
}

/// The nonce an AES-GCM layer uses: the first [`citadel_types::crypto::AES_GCM_NONCE_LENGTH_BYTES`]
/// bytes of `nonce`, or an error when `nonce` is shorter.
pub(crate) fn aes_gcm_nonce(nonce: &[u8]) -> Result<&[u8], Error> {
    nonce
        .get(..citadel_types::crypto::AES_GCM_NONCE_LENGTH_BYTES)
        .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::NonceTooShort))
}
