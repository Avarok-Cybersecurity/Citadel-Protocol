//! The account's sign-in state, as a resume grant is bound to it.

use super::PqAuthRecord;
use citadel_types::auth::{FactorKind, SignInPolicy};
use sha3::{Digest, Sha3_256};

const LABEL: &[u8] = b"citadel-resume-binding-v1";

fn policy_byte(policy: SignInPolicy) -> u8 {
    match policy {
        SignInPolicy::Password => 1,
        SignInPolicy::PasswordAndKey => 2,
        SignInPolicy::KeyOnly => 3,
    }
}

fn kind_byte(kind: FactorKind) -> u8 {
    match kind {
        FactorKind::Password => 1,
        FactorKind::SecurityKey => 2,
        FactorKind::RetiredRecoveryCode(retired) => match retired {},
        FactorKind::RecoveryPhrase => 4,
        FactorKind::ResumeKey => 5,
    }
}

impl PqAuthRecord {
    /// A hash of everything that decides how this account signs in: its policy, its password
    /// salt, and every factor's id, kind, key and whether it is spent. A grant carries the value
    /// from when it was issued; once the two differ the grant is refused, so a changed password,
    /// policy or set of keys ends every grant issued before it, with nothing kept to revoke them.
    /// A factor's label and when it was last used are not part of it.
    pub fn resume_binding(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::default();
        hasher.update(LABEL);
        hasher.update([policy_byte(self.policy)]);
        hasher.update(self.salt_user);
        hasher.update((self.factors.len() as u64).to_be_bytes());
        for factor in &self.factors {
            hasher.update(factor.id.to_be_bytes());
            hasher.update([kind_byte(factor.kind), u8::from(factor.consumed)]);
            hasher.update(factor.ek.fingerprint());
        }
        hasher.finalize().into()
    }
}
