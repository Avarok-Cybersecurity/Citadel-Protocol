//! The server's side of sign-in management: a step-up bound to the operation, a proof of
//! possession for a key being added, then the change itself.

use super::login::{build_login_challenge, AccountAuth, Expectation, Expected};
use super::PqAuthServerSettings;
use crate::auth::pq::kem::{encapsulate, EncapsulationKey, SharedSecret};
use crate::auth::pq::messages::{
    transcript_bytes, ChallengeBody, EnrolChallenge, EnrolProof, FactorChallenges, LoginChallenge,
    ManagementBegin, ManagementChallenge, ManagementCommit, ServerOutcome,
};
use crate::auth::pq::proof::{verify_factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use crate::auth::pq::record::{NewFactor, PqAuthRecord};
use crate::auth::pq::recovery::RECOVERY_CODE_COUNT;
use crate::auth::pq::{management_transcript, policy, random_32};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorId, FactorKind, SessionScope, SignInManagementOp, SignInPolicy};

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
}

/// Starts a change. A recovery session may only make the changes it is allowed.
pub fn begin_management(
    settings: &PqAuthServerSettings,
    cid: u64,
    record: &PqAuthRecord,
    scope: SessionScope,
    begin: ManagementBegin,
) -> Result<(ManagementChallenge, PendingManagement), AccountError> {
    if scope == SessionScope::Recovery && !begin.op.allowed_in_recovery() {
        return Err(error!(ErrorCode::PqSignInRestricted));
    }
    if begin.step_up.recovery.is_some() {
        return Err(malformed("a step-up with a recovery code"));
    }
    let codes = begin.recovery_eks.len();
    match begin.op {
        SignInManagementOp::RegenerateRecoveryCodes if codes != RECOVERY_CODE_COUNT => {
            return Err(malformed("the recovery code count"))
        }
        SignInManagementOp::RegenerateRecoveryCodes => {}
        _ if codes != 0 => return Err(malformed("recovery keys for another change")),
        _ => {}
    }
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
    let challenge = ManagementChallenge { step_up };
    let pending = PendingManagement {
        cid,
        begin,
        challenge: challenge.clone(),
        expected,
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
        let transcript = management_transcript(
            self.cid,
            &self.begin,
            &self.challenge,
            commit.new_key_ek.as_ref(),
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
        let new_key = commit.new_key_ek.clone();
        let change = match (self.begin.op, new_key) {
            (
                SignInManagementOp::AddSecurityKey {
                    credential_id,
                    label,
                },
                Some(ek),
            ) => {
                let (ct, k) = encapsulate(&ek)?;
                let challenge = EnrolChallenge { ct };
                let transcript = TranscriptHash::new(
                    TranscriptPurpose::StepUp,
                    self.cid,
                    &[transcript.as_bytes(), &transcript_bytes(&challenge)],
                );
                let pending = PendingEnrol {
                    key: NewKey {
                        ek,
                        credential_id,
                        label,
                    },
                    k,
                    transcript,
                };
                return Ok(CommitStep::Enrol(challenge, pending));
            }
            (SignInManagementOp::AddSecurityKey { .. }, None) => {
                return Err(malformed("a key to add"))
            }
            (_, Some(_)) => return Err(malformed("a key for another change")),
            (SignInManagementOp::ListCredentials, None) => Change::List,
            (SignInManagementOp::RenameCredential { id, label }, None) => {
                Change::Rename { id, label }
            }
            (SignInManagementOp::RemoveCredential { id }, None) => Change::Remove { id },
            (SignInManagementOp::SetSignInPolicy { policy }, None) => Change::SetPolicy(policy),
            (SignInManagementOp::RegenerateRecoveryCodes, None) => {
                Change::ReplaceRecovery(self.begin.recovery_eks)
            }
        };
        Ok(CommitStep::Ready(change))
    }
}

pub struct NewKey {
    ek: EncapsulationKey,
    credential_id: Vec<u8>,
    label: String,
}

/// A key waiting for its proof of possession.
pub struct PendingEnrol {
    key: NewKey,
    k: SharedSecret,
    transcript: TranscriptHash,
}

impl PendingEnrol {
    /// Nobody enrols a key they do not hold: the tag needs the key's decapsulation of the
    /// ciphertext the server just made.
    pub fn finish(self, proof: &EnrolProof) -> Result<Change, AccountError> {
        if verify_factor_tag(&self.k, ENROL_LABEL, 0, &self.transcript, &proof.tag) {
            Ok(Change::AddKey(self.key))
        } else {
            Err(error!(ErrorCode::PqSignInFailed))
        }
    }
}

/// A verified change, applied under the record lock.
pub enum Change {
    List,
    AddKey(NewKey),
    Rename { id: FactorId, label: String },
    Remove { id: FactorId },
    SetPolicy(SignInPolicy),
    ReplaceRecovery(Vec<EncapsulationKey>),
}

fn checked_label(label: String) -> Result<String, AccountError> {
    let label = label.trim().to_string();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err(policy::refused("a label must be 1 to 64 characters"));
    }
    Ok(label)
}

impl Change {
    pub fn apply(
        self,
        record: &mut PqAuthRecord,
        now_ms: u64,
    ) -> Result<ServerOutcome, AccountError> {
        match self {
            Self::List => Ok(ServerOutcome::Credentials(record.credentials())),
            Self::AddKey(key) => {
                if key.credential_id.is_empty() || key.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
                {
                    return Err(policy::refused("a credential id must be 1 to 1023 bytes"));
                }
                let enrolled = record.factors().iter().any(|f| {
                    f.ek == key.ek || f.credential_id.as_deref() == Some(&key.credential_id)
                });
                if enrolled {
                    return Err(policy::refused("this key is already enrolled"));
                }
                let factor = NewFactor {
                    kind: FactorKind::SecurityKey,
                    ek: key.ek,
                    credential_id: Some(key.credential_id),
                    label: checked_label(key.label)?,
                };
                Ok(ServerOutcome::Added {
                    id: record.add(factor, now_ms),
                })
            }
            Self::Rename { id, label } => {
                record.rename(id, checked_label(label)?)?;
                Ok(ServerOutcome::Renamed)
            }
            Self::Remove { id } => record.remove(id).map(|()| ServerOutcome::Removed),
            Self::SetPolicy(policy) => record.set_policy(policy).map(|()| ServerOutcome::PolicySet),
            Self::ReplaceRecovery(eks) => {
                record.replace_recovery_codes(eks, now_ms);
                Ok(ServerOutcome::RecoveryCodesReplaced)
            }
        }
    }
}
