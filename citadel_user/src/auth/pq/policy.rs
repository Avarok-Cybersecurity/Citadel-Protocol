//! Which factors a policy asks for, and whether a set of factors can give them.

use super::record::Factor;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorKind, SignInPolicy};

pub(crate) fn refused(reason: &'static str) -> AccountError {
    error!(ErrorCode::PqSignInPolicy, reason)
}

/// The kinds a full sign-in under `policy` must prove (one factor of each).
pub fn required_kinds(policy: SignInPolicy) -> &'static [FactorKind] {
    match policy {
        SignInPolicy::Password => &[FactorKind::Password],
        SignInPolicy::PasswordAndKey => &[FactorKind::Password, FactorKind::SecurityKey],
        SignInPolicy::KeyOnly => &[FactorKind::SecurityKey],
    }
}

/// Whether the proven kinds give a full sign-in under `policy`. Recovery codes never do.
pub fn satisfied(policy: SignInPolicy, proven: &[FactorKind]) -> bool {
    required_kinds(policy)
        .iter()
        .all(|kind| proven.contains(kind))
}

/// Whether `factors` hold at least one usable factor of every kind `policy` requires.
pub fn satisfiable(policy: SignInPolicy, factors: &[Factor]) -> bool {
    required_kinds(policy)
        .iter()
        .all(|kind| factors.iter().any(|f| f.kind == *kind && f.usable()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_policy_asks_for_exactly_its_kinds() {
        use FactorKind::*;
        assert!(satisfied(SignInPolicy::Password, &[Password]));
        assert!(!satisfied(SignInPolicy::Password, &[SecurityKey]));
        assert!(!satisfied(SignInPolicy::PasswordAndKey, &[Password]));
        assert!(!satisfied(SignInPolicy::PasswordAndKey, &[SecurityKey]));
        assert!(satisfied(
            SignInPolicy::PasswordAndKey,
            &[SecurityKey, Password]
        ));
        assert!(satisfied(SignInPolicy::KeyOnly, &[SecurityKey]));
        assert!(!satisfied(SignInPolicy::KeyOnly, &[Password, RecoveryCode]));
        for policy in [
            SignInPolicy::Password,
            SignInPolicy::PasswordAndKey,
            SignInPolicy::KeyOnly,
        ] {
            assert!(!satisfied(policy, &[RecoveryCode]));
            assert!(!satisfied(policy, &[]));
        }
    }
}
