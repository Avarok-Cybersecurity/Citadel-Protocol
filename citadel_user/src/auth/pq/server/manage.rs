//! The server's side of sign-in management: a step-up bound to the operation, a proof of
//! possession for a key being added, then the change itself.

use super::change::Change;
use super::login::{build_login_challenge, AccountAuth, Expectation, Expected};
use super::PqAuthServerSettings;
use crate::auth::pq::kem::{encapsulate, EncapsulationKey, SharedSecret};
use crate::auth::pq::messages::{
    transcript_bytes, ChallengeBody, EnrolChallenge, EnrolProof, FactorChallenges, LoginChallenge,
    ManagementBegin, ManagementCeremony, ManagementChallenge, ManagementCommit, ManagementOp,
    NewSecurityKey, SignInLayout,
};
use crate::auth::pq::proof::{verify_factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::recovery::RECOVERY_CODE_COUNT;
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
    let codes = begin.recovery_eks.len();
    match begin.op {
        ManagementOp::RegenerateRecoveryCodes if codes != RECOVERY_CODE_COUNT => {
            return Err(malformed("the recovery code count"))
        }
        ManagementOp::RegenerateRecoveryCodes => {}
        _ if codes != 0 => return Err(malformed("recovery keys for another change")),
        ManagementOp::AddSecurityKey { .. } if settings.security_key_rp_id().is_none() => {
            return Err(error!(
                ErrorCode::PqSignInUnavailable,
                "this server has not enabled security keys"
            ))
        }
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
        }),
    };
    let challenge = ManagementChallenge { step_up, ceremony };
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
        let new_key = match (&commit.new_key_ek, &commit.ceremony) {
            (Some(_), Some(_)) => return Err(malformed("a key in both layouts")),
            (Some(ek), None) => Some(Added::Created(ek.clone())),
            (None, Some(ceremony)) => ceremony.new_key.clone().map(Added::ByCeremony),
            (None, None) => None,
        };
        let change = match (self.begin.op, new_key) {
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
                Change::ReplaceRecovery(self.begin.recovery_eks)
            }
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

/// The proof of possession a key being added must give.
fn enrol(
    cid: u64,
    transcript: TranscriptHash,
    ek: EncapsulationKey,
    credential_id: Vec<u8>,
    label: String,
) -> Result<CommitStep, AccountError> {
    let (ct, k) = encapsulate(&ek)?;
    let challenge = EnrolChallenge { ct };
    let transcript = TranscriptHash::new(
        TranscriptPurpose::StepUp,
        cid,
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
    Ok(CommitStep::Enrol(challenge, pending))
}

pub struct NewKey {
    pub(super) ek: EncapsulationKey,
    pub(super) credential_id: Vec<u8>,
    pub(super) label: String,
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
