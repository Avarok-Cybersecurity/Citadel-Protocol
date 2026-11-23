use super::register::{registration_reply, PendingRegistration};
use super::{decoy, PqAuthServerSettings};
use crate::auth::pq::kem::{encapsulate, EncapsulationKey, SharedSecret};
use crate::auth::pq::messages::{
    ChallengeBody, FactorChallenge, FactorChallenges, LoginChallenge, LoginStart, RegStart,
};
use crate::auth::pq::proof::TranscriptHash;
use crate::auth::pq::random_32;
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::resume::RESUME_FACTOR_ID;
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
    pub(super) secrets: Vec<(FactorId, FactorKind, SharedSecret)>,
    pub(super) rule: Rule,
}

pub(super) enum Rule {
    Policy(SignInPolicy),
    Recovery,
    /// A resume credential's device key, alone (see `server::resume`).
    Resume,
    Decoy,
}

impl Expected {
    pub(super) fn resume(secret: SharedSecret) -> Self {
        Self {
            secrets: vec![(RESUME_FACTOR_ID, FactorKind::ResumeKey, secret)],
            rule: Rule::Resume,
        }
    }

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
    pub(super) expected: Expected,
    pub(super) transcript: TranscriptHash,
}

/// A login whose tags verified and satisfied the account's policy (or used the recovery phrase).
pub struct VerifiedLogin {
    pub scope: SessionScope,
    /// The factors that proved it, for `last_used_ms`.
    pub used: Vec<FactorId>,
    /// Mixed into the session's pre-shared keys on both sides.
    pub session_key: Zeroizing<[u8; 32]>,
    /// Whether the account's own factors proved it. A resumed sign-in did not, and is given no
    /// new resume credential.
    pub by_factors: bool,
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
    build(settings, account, start)
}

/// The challenge of the recovery lane (a device with no bundle): the one recovery factor `start`
/// names, or a decoy shaped like a recovery phrase for an unknown name or fingerprint. A legacy
/// account has no recovery factor, so it is answered as an unknown one.
pub fn build_recovery_challenge(
    settings: &PqAuthServerSettings,
    record: Option<&PqAuthRecord>,
    start: &LoginStart,
) -> Result<(LoginChallenge, Expected), AccountError> {
    if start.recovery.is_none() || start.oprf_blinded.is_some() {
        return Err(error!(ErrorCode::PqSignInMalformed, "a recovery start"));
    }
    let account = record.map_or(AccountAuth::Unknown, AccountAuth::PostQuantum);
    match build(settings, account, start)? {
        (challenge, Expectation::Factors(expected)) => Ok((challenge, expected)),
        _ => Err(error!(ErrorCode::PqSignInMalformed, "a recovery start")),
    }
}

/// An unknown recovery fingerprint is answered with a decoy shaped like a recovery phrase.
fn build(
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
                        // Admission is the login's, already checked; an upgrade is not asked.
                        admission: None,
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
    let real = match (record, start.recovery) {
        (Some(record), None) => Some((policy_targets(record), Rule::Policy(record.policy))),
        (Some(record), Some(fp)) => record
            .recovery_factor(&fp)
            .map(|f| (vec![target(f.id, f.kind, None, &f.ek)], Rule::Recovery)),
        (None, _) => None,
    };
    let (targets, rule) = match real {
        Some(real) => real,
        None => {
            let (id, kind, ek) = match start.recovery {
                None => {
                    let ek = decoy::password_key(settings, &start.username)?;
                    (decoy::PASSWORD_FACTOR_ID, FactorKind::Password, ek)
                }
                Some(fp) => {
                    let (id, ek) = decoy::recovery_factor(settings, &start.username, &fp)?;
                    (id, FactorKind::RecoveryPhrase, ek)
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
