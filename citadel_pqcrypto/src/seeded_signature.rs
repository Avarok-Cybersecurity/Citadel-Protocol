//! ML-DSA-65 keys reproduced from a 32-byte seed (FIPS 204 Alg. 1, `ML-DSA.KeyGen_internal`).
//!
//! A holder that already keeps a secret it can derive the seed from need not store the signing
//! key: the same seed gives the same key on every call.

use zeroize::Zeroizing;

/// The encoded verifying key and the expanded signing key (the encoding
/// [`crate::signature_sign`] takes) for `seed`.
pub fn ml_dsa65_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
    let mut ml_seed = Seed::default();
    ml_seed.copy_from_slice(seed);
    let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&ml_seed);
    zeroize::Zeroize::zeroize(&mut ml_seed[..]);
    let public = sk.verifying_key().encode().as_slice().to_vec();
    // The expanded encoding is what `signature_sign` reads (see `functions::ml_dsa_sign`).
    #[allow(deprecated)]
    let secret = Zeroizing::new(sk.to_expanded().as_slice().to_vec());
    (public, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::crypto::SigAlgorithm;

    #[test]
    fn a_seed_gives_one_key_that_signs_and_verifies() {
        let (public, secret) = ml_dsa65_keypair_from_seed(&[7u8; 32]);
        let (again, _) = ml_dsa65_keypair_from_seed(&[7u8; 32]);
        assert_eq!(public, again);
        let (other, _) = ml_dsa65_keypair_from_seed(&[8u8; 32]);
        assert_ne!(public, other);
        let sig = crate::signature_sign(b"m", secret.as_slice(), SigAlgorithm::MlDsa65).unwrap();
        assert!(crate::signature_verify(b"m", &sig, &public, SigAlgorithm::MlDsa65).is_ok());
        assert!(crate::signature_verify(b"n", &sig, &public, SigAlgorithm::MlDsa65).is_err());
        assert!(crate::signature_verify(b"m", &sig, &other, SigAlgorithm::MlDsa65).is_err());
    }
}
