//! The input check every encapsulation key from elsewhere passes before this crate encapsulates
//! or encrypts to it (FIPS 203 §7.2: the right length, and every coefficient reduced mod q).
//!
//! Each suite uses the backend's own check; a key from an honest generator always passes it,
//! because generation reduces every coefficient before encoding.

use citadel_types::crypto::KemAlgorithm;
use citadel_types::errors::Error;

/// The length of an encapsulation key of `alg`.
pub const fn public_key_len(alg: KemAlgorithm) -> usize {
    match alg {
        KemAlgorithm::MlKem768Fips203 => crate::libcrux_kem::sizes::PK_768,
        KemAlgorithm::MlKem1024Fips203 => crate::libcrux_kem::sizes::PK_1024,
    }
}

/// The length of a ciphertext of `alg`.
pub const fn ciphertext_len(alg: KemAlgorithm) -> usize {
    match alg {
        KemAlgorithm::MlKem768Fips203 => crate::libcrux_kem::sizes::CT_768,
        KemAlgorithm::MlKem1024Fips203 => crate::libcrux_kem::sizes::CT_1024,
    }
}

/// Whether `public_key` is a well-formed encapsulation key for `alg`.
pub fn public_key_is_valid(alg: KemAlgorithm, public_key: &[u8]) -> bool {
    crate::libcrux_kem::public_key_is_valid(alg, public_key)
}

/// Refuses `public_key` unless it is well-formed for `alg`.
pub fn require_valid_public_key(alg: KemAlgorithm, public_key: &[u8]) -> Result<(), Error> {
    if public_key_is_valid(alg, public_key) {
        Ok(())
    } else {
        Err(citadel_io::error!(
            citadel_io::ErrorCode::KemPublicKeyInvalid,
            format!("{alg:?}")
        ))
    }
}

#[cfg(test)]
#[path = "kem_key_check_tests.rs"]
mod tests;
