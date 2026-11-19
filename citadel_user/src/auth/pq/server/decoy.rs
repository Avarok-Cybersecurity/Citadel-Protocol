//! Decoys for a username the server has no post-quantum record for. Every value is derived from
//! the tenant's OPRF seed and the username, so repeated logins for the same unknown name see the
//! same salts and the same factor key, just as they would for a real account. The ciphertexts are
//! fresh encapsulations to that key, as a real account's are.

use super::PqAuthServerSettings;
use crate::auth::pq::kem::{EncapsulationKey, FactorKeypair, FactorSeed, SEED_LEN};
use crate::auth::pq::recovery::RECOVERY_CODE_COUNT;
use crate::misc::AccountError;
use citadel_types::auth::{FactorId, FactorKind};

const SALT_USER: &[u8] = b"citadel-decoy-salt-user-v1";
const PRF_EVAL_SALT: &[u8] = b"citadel-decoy-prf-eval-salt-v1";
const PASSWORD_SEED: &[u8] = b"citadel-decoy-password-factor-v1";
const RECOVERY_SEED: &[u8] = b"citadel-decoy-recovery-factor-v1";
const RECOVERY_PHRASE_SEED: &[u8] = b"citadel-decoy-recovery-phrase-factor-v1";

/// A real account's password factor is the first it is given.
pub(super) const PASSWORD_FACTOR_ID: FactorId = 1;

pub(super) struct DecoyAccount {
    pub salt_user: [u8; 32],
    pub prf_eval_salt: [u8; 32],
}

pub(super) fn account(settings: &PqAuthServerSettings, username: &str) -> DecoyAccount {
    let seed = settings.oprf_seed();
    DecoyAccount {
        salt_user: *seed.derive::<32>(SALT_USER, username),
        prf_eval_salt: *seed.derive::<32>(PRF_EVAL_SALT, username),
    }
}

fn factor_key(
    settings: &PqAuthServerSettings,
    label: &[u8],
    name: &str,
) -> Result<EncapsulationKey, AccountError> {
    let seed = settings.oprf_seed().derive::<SEED_LEN>(label, name);
    let keypair = FactorKeypair::derive(&FactorSeed::new(*seed))?;
    Ok(keypair.encapsulation_key().clone())
}

/// The password factor an unknown username appears to have.
pub(super) fn password_key(
    settings: &PqAuthServerSettings,
    username: &str,
) -> Result<EncapsulationKey, AccountError> {
    factor_key(settings, PASSWORD_SEED, username)
}

/// The recovery factor of `kind` an unknown username (or an unknown fingerprint of a real one)
/// appears to have. A code's id is in the range a real account's codes are numbered in; a
/// phrase's follows them, where a first phrase that replaced the codes is.
pub(super) fn recovery_factor(
    settings: &PqAuthServerSettings,
    username: &str,
    fingerprint: &[u8; 32],
    kind: FactorKind,
) -> Result<(FactorId, EncapsulationKey), AccountError> {
    let codes = RECOVERY_CODE_COUNT as FactorId;
    let (id, label) = match kind {
        FactorKind::RecoveryPhrase => (PASSWORD_FACTOR_ID + 1 + codes, RECOVERY_PHRASE_SEED),
        _ => (
            PASSWORD_FACTOR_ID + 1 + FactorId::from(fingerprint[0]) % codes,
            RECOVERY_SEED,
        ),
    };
    let name = format!("{username}\u{0}{}", hex_of(fingerprint));
    Ok((id, factor_key(settings, label, &name)?))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
