//! The seeds of the factors that need no stretching: a security key's WebAuthn PRF output and a
//! recovery code. (The password's seed needs Argon2id, which only the client runs; see
//! [`super::client::ksf`].)

use super::kem::{FactorSeed, SEED_LEN};
use super::recovery::RecoveryCode;
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

const SECURITY_KEY_SALT: &[u8] = b"citadel-security-key-factor-v1";
const RECOVERY_SALT: &[u8] = b"citadel-recovery-factor-v1";

/// The 32 bytes a security key's WebAuthn PRF extension (`hmac-secret`) returned for one
/// credential and the account's PRF evaluation salt. The embedding application runs the WebAuthn
/// ceremony and hands this over; it never leaves the client.
pub struct PrfOutput(Zeroizing<[u8; 32]>);

impl PrfOutput {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrfOutput(***)")
    }
}

fn expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> FactorSeed {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    Hkdf::<Sha3_256>::new(Some(salt), ikm)
        .expand(info, seed.as_mut())
        .expect("64 bytes is a valid HKDF-SHA3-256 output length");
    FactorSeed::new(*seed)
}

/// HKDF-SHA3 of the PRF output, bound to the credential it came from. The PRF is an HMAC inside
/// the authenticator, so this factor is as post-quantum as the rest; the key's classical
/// assertion signature is not used at all.
pub fn security_key_seed(prf: &PrfOutput, credential_id: &[u8]) -> FactorSeed {
    expand(SECURITY_KEY_SALT, prf.0.as_ref(), credential_id)
}

/// HKDF-SHA3 of a 128-bit recovery code. The code is high-entropy, so it needs no stretching.
pub fn recovery_seed(code: &RecoveryCode) -> FactorSeed {
    expand(RECOVERY_SALT, code.as_bytes(), &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::pq::kem::FactorKeypair;

    fn ek_of(seed: FactorSeed) -> Vec<u8> {
        FactorKeypair::derive(&seed)
            .unwrap()
            .encapsulation_key()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn a_key_factor_depends_on_its_prf_output_and_its_credential() {
        let prf = PrfOutput::new([1u8; 32]);
        let ek = ek_of(security_key_seed(&prf, b"cred-a"));
        assert_eq!(ek, ek_of(security_key_seed(&prf, b"cred-a")));
        assert_ne!(ek, ek_of(security_key_seed(&prf, b"cred-b")));
        assert_ne!(
            ek,
            ek_of(security_key_seed(&PrfOutput::new([2u8; 32]), b"cred-a"))
        );
    }

    #[test]
    fn recovery_codes_give_distinct_stable_factors() {
        let code = RecoveryCode::generate();
        assert_eq!(ek_of(recovery_seed(&code)), ek_of(recovery_seed(&code)));
        assert_ne!(
            ek_of(recovery_seed(&code)),
            ek_of(recovery_seed(&RecoveryCode::generate()))
        );
    }
}
