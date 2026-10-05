//! # The auth-migration pattern
//!
//! A stored sign-in record changes shape the way a database schema does, with one difference: a
//! record moves only when its own account proves itself, because a new shape may need what only
//! a proof establishes. The rules:
//!
//! 1. **Append a version.** A new shape is a new variant at the end of
//!    [`super::stored::StoredAuthMode`], so its index (the version) is higher than every other.
//!    Older variants stay readable.
//! 2. **Move at proof time.** After a sign-in has verified against the record as it is, the
//!    server hands what the proof established to [`upgrade_at_proof`], under the record lock, and
//!    saves the result (`AccountManager::record_pq_sign_in`). Nothing migrates in bulk, and an
//!    account that never signs in again keeps its version.
//! 3. **One way.** [`upgrade_at_proof`] refuses any step that does not raise the version, so no
//!    code path downgrades a record or loops.
//! 4. **Retire last.** Once the server confirms no record of an old version remains, that
//!    version's verifier is deleted and its variant becomes read-only, refused at load. The
//!    Argon2 sunset did this to version 0 (see [`super::stored`]).
//!
//! A new version implements [`VersionedAuthRecord::migrate`] for the step into it; the hook, the
//! lock and the save stay as they are.

use super::stored::{POST_QUANTUM_VERSION, TRANSIENT_VERSION};
use super::DeclaredAuthenticationMode;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::FactorId;

/// A record that migrates at proof time.
pub trait VersionedAuthRecord: Sized {
    /// What a proof that verified hands the hook.
    type Proven;

    /// The version this record is stored as.
    fn version(&self) -> u32;

    /// The record one version on, given the proof that verified against this one, or `None`
    /// when this version is current.
    fn migrate(&self, proven: &Self::Proven) -> Result<Option<Self>, AccountError>;
}

/// Moves `record` forward until it is current. `Ok(true)` when it changed and must be saved.
pub fn upgrade_at_proof<V: VersionedAuthRecord>(
    record: &mut V,
    proven: &V::Proven,
) -> Result<bool, AccountError> {
    let mut changed = false;
    while let Some(next) = record.migrate(proven)? {
        if next.version() <= record.version() {
            return Err(error!(
                ErrorCode::PqSignInMalformed,
                format!(
                    "an auth migration from version {} to {}",
                    record.version(),
                    next.version()
                )
            ));
        }
        *record = next;
        changed = true;
    }
    Ok(changed)
}

/// What a verified post-quantum sign-in established.
pub struct ProvenSignIn {
    /// The factors that proved it.
    pub used: Vec<FactorId>,
    pub now_ms: u64,
}

impl VersionedAuthRecord for DeclaredAuthenticationMode {
    type Proven = ProvenSignIn;

    fn version(&self) -> u32 {
        match self {
            Self::Transient { .. } => TRANSIENT_VERSION,
            Self::PostQuantum { .. } => POST_QUANTUM_VERSION,
        }
    }

    /// Both versions are current.
    fn migrate(&self, _proven: &Self::Proven) -> Result<Option<Self>, AccountError> {
        Ok(None)
    }
}

#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;
