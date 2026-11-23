//! The server's check of a login's tags against the challenge it issued.

use super::login::{PendingLogin, Rule, VerifiedLogin};
use crate::auth::pq::messages::LoginFinish;
use crate::auth::pq::policy;
use crate::auth::pq::proof::{self, AUTH_LABEL};
use crate::auth::pq::record::is_recovery;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;

impl PendingLogin {
    /// Checks every tag (all of them, before deciding) and then the policy. Any failure is the
    /// same [`ErrorCode::PqSignInFailed`].
    pub fn verify(self, finish: &LoginFinish) -> Result<VerifiedLogin, AccountError> {
        let failed = || error!(ErrorCode::PqSignInFailed);
        let mut all_valid = !finish.tags.is_empty();
        let mut used = Vec::with_capacity(finish.tags.len());
        let mut kinds = Vec::with_capacity(finish.tags.len());
        let mut secrets = Vec::with_capacity(finish.tags.len());
        for presented in &finish.tags {
            let expected = self
                .expected
                .secrets
                .iter()
                .find(|(id, _, _)| *id == presented.factor_id);
            let Some((id, kind, k)) = expected else {
                all_valid = false;
                continue;
            };
            all_valid &= !used.contains(id);
            all_valid &=
                proof::verify_factor_tag(k, AUTH_LABEL, *id, &self.transcript, &presented.tag);
            used.push(*id);
            kinds.push(*kind);
            secrets.push(k);
        }
        let by_factors = matches!(self.expected.rule, Rule::Policy(_));
        // A device's resume key is no factor of the account: the record has nothing to mark.
        let recorded = !matches!(self.expected.rule, Rule::Resume);
        let scope = match self.expected.rule {
            Rule::Policy(policy) if policy::satisfied(policy, &kinds) => SessionScope::Full,
            // Its one secret is the device key's, so tags that all verify are that key's.
            Rule::Resume => SessionScope::Full,
            Rule::Recovery if matches!(kinds[..], [kind] if is_recovery(kind)) => {
                SessionScope::Recovery
            }
            _ => return Err(failed()),
        };
        if !all_valid {
            return Err(failed());
        }
        Ok(VerifiedLogin {
            scope,
            session_key: proof::session_key(&secrets, &self.transcript),
            used: used.into_iter().filter(|_| recorded).collect(),
            by_factors,
        })
    }
}
