//! The server's side of sign-in management: a step-up bound to the operation, a proof of
//! possession for a key being added, then the change itself.

use super::change::Change;
use super::enrol::enrol;
pub use super::enrol::{NewKey, PendingEnrol};
use super::login::{build_login_challenge, AccountAuth, Expectation, Expected};
use super::register::{registration_reply, PendingRegistration};
use super::PqAuthServerSettings;
use crate::auth::pq::kem::EncapsulationKey;
use crate::auth::pq::messages::{
    ChallengeBody, EnrolChallenge, FactorChallenges, LoginChallenge, ManagementBegin,
    ManagementCeremony, ManagementChallenge, ManagementCommit, ManagementOp, NewSecurityKey,
    RegStart, SignInLayout,
};
use crate::auth::pq::record::{PqAuthRecord, RecoverySecret};
use crate::auth::pq::{management_transcript, random_32};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorKind, SessionScope};

/// The longest label a factor may carry.
pub const MAX_LABEL_CHARS: usize = 64;
/// WebAuthn caps a credential id at 1023 bytes.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

fn malformed(what: &'static str) -> AccountError {
    error!(ErrorCode::PqSignInMalformed, what)
}

/// A management exchange between `Challenge` and `Commit`.
pub struct PendingManagement {
    cid: u64,
    begin: ManagementBegin,
    challenge: ManagementChallenge,
    /// `None` in a recovery session, which proves no factor again.
    expected: Option<Expected>,
    /// `SetPassword`: the salt and parameters the new factor is stretched with.
    password: Option<PendingRegistration>,
}

/// Starts a change, answering in the client's `layout`. A recovery session may only make the
/// changes it is allowed.
pub fn begin_management(
    settings: &PqAuthServerSettings,
    cid: u64,
    record: &PqAuthRecord,
    scope: SessionScope,
    begin: ManagementBegin,
    layout: SignInLayout,
) -> Result<(ManagementChallenge, PendingManagement), AccountError> {
    if begin.op.layout().is_some_and(|needed| needed != layout) {
        return Err(malformed("a change from another protocol version"));
    }
    if scope == SessionScope::Recovery && !begin.op.allowed_in_recovery() {
        return Err(error!(ErrorCode::PqSignInRestricted));
    }
    if begin.step_up.recovery.is_some() {
        return Err(malformed("a step-up with a recovery code"));
    }
    if begin.recovery_eks.len() != begin.op.recovery_key_count() {
        return Err(malformed("the recovery key count"));
    }
    let password = match &begin.op {
        ManagementOp::AddSecurityKey { .. } if settings.security_key_rp_id().is_none() => {
            return Err(error!(
                ErrorCode::PqSignInUnavailable,
                "this server has not enabled security keys"
            ))
        }
        ManagementOp::SetPassword { oprf_blinded } => {
            let start = RegStart {
                username: begin.step_up.username.clone(),
                oprf_blinded: oprf_blinded.clone(),
                admission: None,
                reads_challenge: false,
            };
            let (mut reply, pending) = registration_reply(settings, &start)?;
            // Only the password changes; the account's keys keep their PRF salt.
            reply.prf_eval_salt = record.prf_eval_salt;
            Some((reply, pending))
        }
        _ => None,
    };
    let (step_up, expected) = match scope {
        SessionScope::Full => {
            let account = AccountAuth::PostQuantum(record);
            match build_login_challenge(settings, account, &begin.step_up)? {
                (challenge, Expectation::Factors(expected)) => (challenge, Some(expected)),
                _ => return Err(malformed("a step-up for a legacy account")),
            }
        }
        SessionScope::Recovery => (recovery_challenge(record), None),
    };
    let ceremony = match layout {
        SignInLayout::V0_12_2 => None,
        SignInLayout::SecurityKeyCeremony => Some(ManagementCeremony {
            rp_id: settings.security_key_rp_id().map(str::to_owned),
            exclude_credentials: match begin.op {
                ManagementOp::AddSecurityKey { .. } => record
                    .usable(FactorKind::SecurityKey)
                    .filter_map(|key| key.credential_id.clone())
                    .collect(),
                _ => Vec::new(),
            },
            password: password.as_ref().map(|(reply, _)| reply.clone()),
        }),
    };
    let challenge = ManagementChallenge { step_up, ceremony };
    let pending = PendingManagement {
        cid,
        begin,
        challenge: challenge.clone(),
        expected,
        password: password.map(|(_, pending)| pending),
    };
    Ok((challenge, pending))
}

/// A recovery session's step-up challenges nothing, but still tells the client the account's PRF
/// salt, which it needs to derive a key it is adding.
fn recovery_challenge(record: &PqAuthRecord) -> LoginChallenge {
    LoginChallenge {
        server_nonce: random_32(),
        body: ChallengeBody::Factors(FactorChallenges {
            oprf_evaluated: None,
            salt_user: record.salt_user,
            prf_eval_salt: record.prf_eval_salt,
            ksf: record.ksf,
            challenges: Vec::new(),
        }),
    }
}

/// What comes after a verified `Commit`.
pub enum CommitStep {
    Ready(Change),
    /// `AddSecurityKey`: the key must prove itself first.
    Enrol(EnrolChallenge, PendingEnrol),
}

impl PendingManagement {
    pub fn commit(self, commit: &ManagementCommit) -> Result<CommitStep, AccountError> {
        if commit.ceremony.is_some() != self.challenge.ceremony.is_some() {
            return Err(malformed("a commit in another layout than its challenge"));
        }
        let transcript = management_transcript(
            self.cid,
            &self.begin,
            &self.challenge,
            &commit.key_binding(),
        );
        match self.expected {
            Some(expected) => {
                let verified = expected.bind(transcript).verify(&commit.step_up)?;
                if verified.scope != SessionScope::Full {
                    return Err(error!(ErrorCode::PqSignInFailed));
                }
            }
            None if commit.step_up.tags.is_empty() => {}
            None => return Err(malformed("step-up tags in a recovery session")),
        }
        let password_ek = commit.ceremony.as_ref().and_then(|c| c.password_ek.clone());
        let change = match (self.begin.op, self.password, password_ek) {
            (ManagementOp::SetPassword { .. }, Some(pending), Some(ek)) => {
                let (salt_user, ksf) = pending.password_parts();
                return Ok(CommitStep::Ready(Change::SetPassword {
                    ek,
                    salt_user,
                    ksf,
                }));
            }
            (ManagementOp::SetPassword { .. }, ..) => {
                return Err(malformed("a new password's key"))
            }
            (_, _, Some(_)) => return Err(malformed("a password for another change")),
            (op, ..) => op,
        };
        let recovery_eks = self.begin.recovery_eks;
        let new_key = match (&commit.new_key_ek, &commit.ceremony) {
            (Some(_), Some(_)) => return Err(malformed("a key in both layouts")),
            (Some(ek), None) => Some(Added::Created(ek.clone())),
            (None, Some(ceremony)) => ceremony.new_key.clone().map(Added::ByCeremony),
            (None, None) => None,
        };
        let change = match (change, new_key) {
            (ManagementOp::AddSecurityKey { label }, Some(Added::ByCeremony(new_key))) => {
                let NewSecurityKey { credential_id, ek } = new_key;
                return enrol(self.cid, transcript, ek, credential_id, label);
            }
            (
                ManagementOp::AddCreatedSecurityKey {
                    credential_id,
                    label,
                },
                Some(Added::Created(ek)),
            ) => return enrol(self.cid, transcript, ek, credential_id, label),
            (ManagementOp::AddSecurityKey { .. }, _)
            | (ManagementOp::AddCreatedSecurityKey { .. }, _) => {
                return Err(malformed("a key to add"))
            }
            (_, Some(_)) => return Err(malformed("a key for another change")),
            (ManagementOp::ListCredentials, None) => Change::List,
            (ManagementOp::RenameCredential { id, label }, None) => Change::Rename { id, label },
            (ManagementOp::RemoveCredential { id }, None) => Change::Remove { id },
            (ManagementOp::SetSignInPolicy { policy }, None) => Change::SetPolicy(policy),
            (ManagementOp::RegenerateRecoveryCodes, None) => {
                Change::ReplaceRecovery(RecoverySecret::Codes(recovery_eks))
            }
            (ManagementOp::RegenerateRecoveryPhrase, None) => {
                let ek = recovery_eks.into_iter().next();
                let ek = ek.ok_or_else(|| malformed("the recovery key count"))?;
                Change::ReplaceRecovery(RecoverySecret::Phrase(ek))
            }
            (ManagementOp::SetPassword { .. }, None) => return Err(malformed("a new password")),
        };
        Ok(CommitStep::Ready(change))
    }
}

/// The key a commit adds, in either layout.
enum Added {
    /// 0.12.2: the credential id came in `Begin`.
    Created(EncapsulationKey),
    ByCeremony(NewSecurityKey),
}
