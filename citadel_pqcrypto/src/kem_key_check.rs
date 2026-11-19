//! The input check every encapsulation key from elsewhere passes before this crate encapsulates
//! or encrypts to it (FIPS 203 §7.2: the right length, and every coefficient reduced mod q).
//!
//! The FIPS 203 suites use the backend's own check. Round-3 Kyber (`MlKem`) has the same key
//! encoding (12-bit coefficients, then a 32-byte seed), so the same reduction check applies; a
//! key from an honest generator always passes it, because generation reduces every coefficient
//! before encoding.

use citadel_types::crypto::KemAlgorithm;
use citadel_types::errors::Error;

/// The modulus every encoded coefficient must be below.
const Q: u16 = 3329;
/// Bytes per encoded polynomial: 256 coefficients at 12 bits.
const POLY_BYTES: usize = 384;

/// Whether `public_key` is a well-formed encapsulation key for `alg`.
pub fn public_key_is_valid(alg: KemAlgorithm, public_key: &[u8]) -> bool {
    match alg {
        KemAlgorithm::MlKem => round3_public_key_is_valid(public_key),
        KemAlgorithm::MlKem768Fips203 | KemAlgorithm::MlKem1024Fips203 => {
            crate::libcrux_kem::public_key_is_valid(alg, public_key)
        }
    }
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

fn round3_public_key_is_valid(public_key: &[u8]) -> bool {
    public_key.len() == pqc_kyber::KYBER_PUBLICKEYBYTES
        && coefficients_are_reduced(&public_key[..pqc_kyber::KYBER_K * POLY_BYTES])
}

/// Each 3 bytes hold two little-endian 12-bit coefficients.
fn coefficients_are_reduced(encoded: &[u8]) -> bool {
    let (triples, _) = encoded.as_chunks::<3>();
    triples.iter().all(|c| {
        let first = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let second = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        first < Q && second < Q
    })
}

#[cfg(test)]
#[path = "kem_key_check_tests.rs"]
mod tests;
