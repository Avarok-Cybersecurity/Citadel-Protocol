//! The recovery phrase as a sign-in factor.
//!
//! ```text
//! seed       : 32 bytes                -- drawn by the client, or derived from an identity seed
//! phrase     = citadel_phrase::phrase_encode(seed)                     -- 24 words, shown once
//! factor     = HKDF-SHA3-256(salt = "citadel-recovery-phrase-factor-v1", ikm = seed,
//!                            info = u16be(len(domain)) ‖ domain ‖ 0x00 ‖ username)   -- 64 bytes
//! (dk, ek)   = ML-KEM-1024.KeyGen(factor)
//! ```
//!
//! The server stores only `ek`. The `info` binds the factor to one server and one username, so one
//! seed gives unrelated factors everywhere it is used. The seed is also the account's RE-VFS root
//! (`citadel_crypt::revfs_seal::RevfsKey::derive`), so recovering the phrase recovers the files.
//! 256 random bits need no stretching, so nothing here runs Argon2.

use super::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use crate::misc::AccountError;
use citadel_crypt::revfs_seal::domain_bound_info;
use citadel_io::{error, ErrorCode};
use hkdf::Hkdf;
use rand::RngCore;
use sha3::Sha3_256;
use zeroize::Zeroizing;

const PHRASE_FACTOR_SALT: &[u8] = b"citadel-recovery-phrase-factor-v1";

/// The 32-byte seed a recovery phrase encodes.
#[derive(Clone)]
pub struct RecoverySeed(Zeroizing<[u8; 32]>);

impl RecoverySeed {
    /// A fresh seed, for a new phrase. Only a client draws one.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(seed.as_mut());
        Self(seed)
    }

    /// A seed the application already holds (an identity's recovery sub-key, for instance).
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    /// Reads a phrase as the user typed it: case and the spacing between words do not matter.
    /// The error says what is wrong with the words, never anything about an account.
    pub fn parse(typed: &str) -> Result<Self, AccountError> {
        let lowered = Zeroizing::new(typed.to_lowercase());
        let words: Vec<&str> = lowered.split_whitespace().collect();
        citadel_phrase::phrase_decode(&words)
            .map(Self::from_bytes)
            .map_err(|err| error!(ErrorCode::RecoveryPhraseUnreadable, err.to_string()))
    }

    /// The 24 words, to show the user once.
    pub fn words(&self) -> Vec<String> {
        citadel_phrase::phrase_encode(&self.0)
            .iter()
            .map(|word| (*word).to_string())
            .collect()
    }

    /// The seed itself: the root of the account's RE-VFS key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for RecoverySeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySeed(***)")
    }
}

/// A recovery phrase as one server knows it: the seed, and the server's canonical domain the
/// factor is bound to. The caller canonicalises the domain (the SDK resolves no names).
#[derive(Clone)]
pub struct RecoveryPhrase {
    seed: RecoverySeed,
    canonical_domain: String,
}

impl RecoveryPhrase {
    pub fn new(
        seed: RecoverySeed,
        canonical_domain: impl Into<String>,
    ) -> Result<Self, AccountError> {
        let canonical_domain = canonical_domain.into();
        if domain_bound_info(&canonical_domain, &[]).is_none() {
            return Err(error!(ErrorCode::RecoveryDomainInvalid));
        }
        Ok(Self {
            seed,
            canonical_domain,
        })
    }

    pub fn seed(&self) -> &RecoverySeed {
        &self.seed
    }

    pub fn canonical_domain(&self) -> &str {
        &self.canonical_domain
    }

    /// The factor's keypair for `username` on this phrase's server.
    pub fn keypair(&self, username: &str) -> Result<FactorKeypair, AccountError> {
        FactorKeypair::derive(&phrase_factor_seed(
            self.seed.as_bytes(),
            &self.canonical_domain,
            username,
        )?)
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("seed", &self.seed)
            .field("canonical_domain", &self.canonical_domain)
            .finish()
    }
}

/// The phrase factor's seed for `username` on the server at `canonical_domain`.
pub fn phrase_factor_seed(
    seed: &[u8; 32],
    canonical_domain: &str,
    username: &str,
) -> Result<FactorSeed, AccountError> {
    let info = domain_bound_info(canonical_domain, username.as_bytes())
        .ok_or_else(|| error!(ErrorCode::RecoveryDomainInvalid))?;
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    Hkdf::<Sha3_256>::new(Some(PHRASE_FACTOR_SALT), seed)
        .expand(&info, out.as_mut())
        .map_err(|_| error!(ErrorCode::PqSignInCrypto, "HKDF output length"))?;
    Ok(FactorSeed::new(*out))
}
