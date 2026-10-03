use super::register::{registration_reply, PendingRegistration};
use super::{decoy, PqAuthServerSettings};
use crate::auth::pq::kem::{encapsulate, EncapsulationKey, SharedSecret};
use crate::auth::pq::messages::{
    ChallengeBody, FactorChallenge, FactorChallenges, LoginChallenge, LoginFinish, LoginStart,
    RegStart,
};
use crate::auth::pq::proof::{self, TranscriptHash, AUTH_LABEL};
use crate::auth::pq::random_32;
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::{oprf, policy};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorId, FactorKind, SessionScope, SignInPolicy};
use zeroize::Zeroizing;

/// What the server knows about the account a login names.
pub enum AccountAuth<'a> {
    PostQuantum(&'a PqAuthRecord),
    /// A legacy Argon2 record: the login is checked the legacy way, and may upgrade.
    Legacy,
    /// No such account. The login gets decoys and cannot succeed.
    Unknown,
}

/// What the server expects back for a challenge it issued, before the transcript is fixed.
pub enum Expectation {
    Factors(Expected),
    Legacy {
        upgrade: Option<PendingRegistration>,
    },
}

pub struct Expected {
    secrets: Vec<(FactorId, FactorKind, SharedSecret)>,
    rule: Rule,
}

enum Rule {
    Policy(SignInPolicy),
    Recovery,
    Decoy,
}

impl Expected {
    /// Fixes the transcript the tags must be bound to.
    pub fn bind(self, transcript: TranscriptHash) -> PendingLogin {
        PendingLogin {
            expected: self,
            transcript,
        }
    }
}

/// A challenge waiting for its tags.
pub struct PendingLogin {
    expected: Expected,
    transcript: TranscriptHash,
}

/// A login whose tags verified and satisfied the account's policy (or used a recovery code).
pub struct VerifiedLogin {
    pub scope: SessionScope,
    /// The factors that proved it, for `last_used_ms` and to consume a recovery code.
    pub used: Vec<FactorId>,
    /// Mixed into the session's pre-shared keys on both sides.
    pub session_key: Zeroizing<[u8; 32]>,
}

struct Target<'a> {
    factor_id: FactorId,
    kind: FactorKind,
    credential_id: Option<Vec<u8>>,
    ek: &'a EncapsulationKey,
}

/// Builds the challenge for `start`. The server's work: at most one OPRF evaluation, and one
/// encapsulation per factor it challenges.
pub fn build_login_challenge(
    settings: &PqAuthServerSettings,
    account: AccountAuth<'_>,
    start: &LoginStart,
) -> Result<(LoginChallenge, Expectation), AccountError> {
    let server_nonce = random_32();
    let record = match account {
        AccountAuth::Legacy => {
            let upgrade = match (&start.oprf_blinded, &start.recovery) {
                (Some(blinded), None) => Some(registration_reply(
                    settings,
                    &RegStart {
                        username: start.username.clone(),
                        oprf_blinded: blinded.clone(),
                    },
                )?),
                _ => None,
            };
            let (reply, pending) = upgrade.map_or((None, None), |(r, p)| (Some(r), Some(p)));
            let challenge = LoginChallenge {
                server_nonce,
                body: ChallengeBody::Legacy { upgrade: reply },
            };
            return Ok((challenge, Expectation::Legacy { upgrade: pending }));
        }
        AccountAuth::PostQuantum(record) => Some(record),
        AccountAuth::Unknown => None,
    };

    let oprf_evaluated = match &start.oprf_blinded {
        Some(blinded) => Some(oprf::server_evaluate(
            settings.oprf_seed(),
            &start.username,
            blinded,
        )?),
        None => None,
    };

    let decoy = decoy::account(settings, &start.username);
    let decoy_key;
    let (salt_user, prf_eval_salt, ksf) = match record {
        Some(r) => (r.salt_user, r.prf_eval_salt, r.ksf),
        None => (decoy.salt_user, decoy.prf_eval_salt, settings.ksf()),
    };
    let (targets, rule) = match (record, start.recovery) {
        (Some(record), None) => (policy_targets(record), Rule::Policy(record.policy)),
        (Some(record), Some(fp)) => match record
            .usable(FactorKind::RecoveryCode)
            .find(|f| f.ek.fingerprint() == fp)
        {
            Some(code) => (
                vec![target(code.id, code.kind, None, &code.ek)],
                Rule::Recovery,
            ),
            None => {
                let (id, ek) = decoy::recovery_factor(settings, &start.username, &fp)?;
                decoy_key = ek;
                (
                    vec![target(id, FactorKind::RecoveryCode, None, &decoy_key)],
                    Rule::Decoy,
                )
            }
        },
        (None, recovery) => {
            let (id, kind, ek) = match recovery {
                None => {
                    let ek = decoy::password_key(settings, &start.username)?;
                    (decoy::PASSWORD_FACTOR_ID, FactorKind::Password, ek)
                }
                Some(fp) => {
                    let (id, ek) = decoy::recovery_factor(settings, &start.username, &fp)?;
                    (id, FactorKind::RecoveryCode, ek)
                }
            };
            decoy_key = ek;
            (vec![target(id, kind, None, &decoy_key)], Rule::Decoy)
        }
    };

    let mut challenges = Vec::with_capacity(targets.len());
    let mut secrets = Vec::with_capacity(targets.len());
    for t in targets {
        let (ct, k) = encapsulate(t.ek)?;
        challenges.push(FactorChallenge {
            factor_id: t.factor_id,
            kind: t.kind,
            credential_id: t.credential_id,
            ct,
        });
        secrets.push((t.factor_id, t.kind, k));
    }

    let challenge = LoginChallenge {
        server_nonce,
        body: ChallengeBody::Factors(FactorChallenges {
            oprf_evaluated,
            salt_user,
            prf_eval_salt,
            ksf,
            challenges,
        }),
    };
    Ok((challenge, Expectation::Factors(Expected { secrets, rule })))
}

fn target(
    factor_id: FactorId,
    kind: FactorKind,
    credential_id: Option<Vec<u8>>,
    ek: &EncapsulationKey,
) -> Target<'_> {
    Target {
        factor_id,
        kind,
        credential_id,
        ek,
    }
}

/// Every usable factor of every kind the policy requires: the client proves one of each.
fn policy_targets(record: &PqAuthRecord) -> Vec<Target<'_>> {
    policy::required_kinds(record.policy)
        .iter()
        .flat_map(|kind| record.usable(*kind))
        .map(|f| target(f.id, f.kind, f.credential_id.clone(), &f.ek))
        .collect()
}

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
        let scope = match self.expected.rule {
            Rule::Policy(policy) if policy::satisfied(policy, &kinds) => SessionScope::Full,
            Rule::Recovery if kinds == [FactorKind::RecoveryCode] => SessionScope::Recovery,
            _ => return Err(failed()),
        };
        if !all_valid {
            return Err(failed());
        }
        Ok(VerifiedLogin {
            scope,
            session_key: proof::session_key(&secrets, &self.transcript),
            used,
        })
    }
}
