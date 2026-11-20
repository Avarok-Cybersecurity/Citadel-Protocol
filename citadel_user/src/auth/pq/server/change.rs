//! A verified management change, and how it is applied to the record.

use super::manage::{NewKey, MAX_CREDENTIAL_ID_BYTES, MAX_LABEL_CHARS};
use crate::auth::pq::kem::EncapsulationKey;
use crate::auth::pq::messages::ServerOutcome;
use crate::auth::pq::policy;
use crate::auth::pq::record::{KsfParams, NewFactor, PqAuthRecord, RecoverySecret};
use crate::misc::AccountError;
use citadel_types::auth::{FactorId, FactorKind, SignInPolicy};

/// A verified change, applied under the record lock.
pub enum Change {
    List,
    AddKey(NewKey),
    Rename {
        id: FactorId,
        label: String,
    },
    Remove {
        id: FactorId,
    },
    SetPolicy(SignInPolicy),
    ReplaceRecovery(RecoverySecret),
    SetPassword {
        ek: EncapsulationKey,
        salt_user: [u8; 32],
        ksf: KsfParams,
    },
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
            Self::List => Ok(ServerOutcome::Credentials {
                policy: record.policy,
                credentials: record.credentials(),
            }),
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
            Self::ReplaceRecovery(secret) => {
                let outcome = match &secret {
                    RecoverySecret::Codes(_) => ServerOutcome::RecoveryCodesReplaced,
                    RecoverySecret::Phrase(_) => ServerOutcome::RecoveryPhraseReplaced,
                };
                record.replace_recovery(secret, now_ms);
                Ok(outcome)
            }
            Self::SetPassword { ek, salt_user, ksf } => {
                record.set_password(ek, salt_user, ksf, now_ms);
                Ok(ServerOutcome::PasswordSet)
            }
        }
    }
}
