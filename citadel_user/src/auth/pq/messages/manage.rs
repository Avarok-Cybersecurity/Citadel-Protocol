use super::login::{LoginChallenge, LoginFinish, LoginStart};
use super::{transcript_bytes, SignInLayout};
use crate::auth::pq::kem::{EncapsulationKey, KemCiphertext};
use crate::auth::pq::proof::Tag;
use citadel_negotiation::frame::appended_field;
use citadel_types::auth::{FactorId, SignInCredential, SignInManagementOp, SignInPolicy};
use serde::{Deserialize, Serialize};

/// The management exchange, in an authenticated session:
/// `Begin` → `Challenge` → `Commit` → (`EnrolChallenge` → `EnrolProof`, to add a key) → `Done`.
///
/// The step-up is a login challenge bound to the operation, so a proof made for one change cannot
/// authorize another. A key being added is proven separately, after the step-up, because the
/// client can only create it once the challenge has told it the relying party and PRF salt.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ManagementMessage {
    Begin(ManagementBegin),
    Challenge(ManagementChallenge),
    Commit(ManagementCommit),
    EnrolChallenge(EnrolChallenge),
    EnrolProof(EnrolProof),
    Done(ManagementDone),
}

/// C→S.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementBegin {
    pub op: ManagementOp,
    /// The step-up. A recovery session sends one too; the server challenges no factor in it.
    pub step_up: LoginStart,
    /// `RegenerateRecoveryCodes`: the new codes' keys.
    pub recovery_eks: Vec<EncapsulationKey>,
}

/// A change on the wire: [`SignInManagementOp`] in 0.12.2's variant order, with the one variant
/// [`SignInLayout::SecurityKeyCeremony`] added appended last, so a 0.12.2 peer's index for every
/// other variant is unchanged.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ManagementOp {
    ListCredentials,
    /// 0.12.2's enrolment: the application created the credential before the exchange.
    AddCreatedSecurityKey {
        credential_id: Vec<u8>,
        label: String,
    },
    RenameCredential {
        id: FactorId,
        label: String,
    },
    RemoveCredential {
        id: FactorId,
    },
    SetSignInPolicy {
        policy: SignInPolicy,
    },
    RegenerateRecoveryCodes,
    /// The client creates the credential once the challenge has named the relying party.
    AddSecurityKey {
        label: String,
    },
}

impl From<SignInManagementOp> for ManagementOp {
    fn from(op: SignInManagementOp) -> Self {
        match op {
            SignInManagementOp::ListCredentials => Self::ListCredentials,
            SignInManagementOp::AddSecurityKey { label } => Self::AddSecurityKey { label },
            SignInManagementOp::RenameCredential { id, label } => {
                Self::RenameCredential { id, label }
            }
            SignInManagementOp::RemoveCredential { id } => Self::RemoveCredential { id },
            SignInManagementOp::SetSignInPolicy { policy } => Self::SetSignInPolicy { policy },
            SignInManagementOp::RegenerateRecoveryCodes => Self::RegenerateRecoveryCodes,
        }
    }
}

impl ManagementOp {
    /// Whether a session signed in with a recovery code may make this change.
    pub fn allowed_in_recovery(&self) -> bool {
        matches!(
            self,
            Self::AddCreatedSecurityKey { .. }
                | Self::AddSecurityKey { .. }
                | Self::SetSignInPolicy { .. }
        )
    }

    /// The layout a peer must speak to send this change.
    pub fn layout(&self) -> Option<SignInLayout> {
        match self {
            Self::AddCreatedSecurityKey { .. } => Some(SignInLayout::V0_12_2),
            Self::AddSecurityKey { .. } => Some(SignInLayout::SecurityKeyCeremony),
            _ => None,
        }
    }
}

/// S→C.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementChallenge {
    pub step_up: LoginChallenge,
    /// Appended: absent for a 0.12.2 peer, so it reads these bytes exactly as it always did.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "appended_field"
    )]
    pub ceremony: Option<ManagementCeremony>,
}

/// What a management challenge tells a client that runs the security-key ceremony.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCeremony {
    /// The relying party the step-up's keys, and a key being added, are scoped to.
    pub rp_id: Option<String>,
    /// `AddSecurityKey`: the credential ids of the account's keys. The new credential is not
    /// created on an authenticator that holds one of them, so no key is enrolled twice.
    pub exclude_credentials: Vec<Vec<u8>>,
}

impl ManagementChallenge {
    /// The layout the server chose, which the client answers in.
    pub fn layout(&self) -> SignInLayout {
        match self.ceremony {
            Some(_) => SignInLayout::SecurityKeyCeremony,
            None => SignInLayout::V0_12_2,
        }
    }
}

/// C→S. The step-up tags are bound to `Begin`, `Challenge` and the key being added together.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCommit {
    pub step_up: LoginFinish,
    /// 0.12.2's `AddCreatedSecurityKey`: the new key's encapsulation key. Always `None` in
    /// [`SignInLayout::SecurityKeyCeremony`], which carries the key in `ceremony`.
    pub new_key_ek: Option<EncapsulationKey>,
    /// Appended: absent for a 0.12.2 peer, so it reads these bytes exactly as it always did.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "appended_field"
    )]
    pub ceremony: Option<CommitCeremony>,
}

/// What a client that runs the security-key ceremony commits to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommitCeremony {
    /// `AddSecurityKey`: the key the client created.
    pub new_key: Option<NewSecurityKey>,
}

impl ManagementCommit {
    /// The bytes of the key this commit adds, as its transcript binds them.
    pub fn key_binding(&self) -> Vec<u8> {
        key_binding(&self.new_key_ek, self.ceremony.as_ref())
    }
}

/// 0.12.2 binds the bare encapsulation key; the ceremony binds the created key with its
/// credential id.
pub(crate) fn key_binding(
    new_key_ek: &Option<EncapsulationKey>,
    ceremony: Option<&CommitCeremony>,
) -> Vec<u8> {
    match ceremony {
        Some(ceremony) => transcript_bytes(&ceremony.new_key),
        None => transcript_bytes(new_key_ek),
    }
}

/// A security key being added: its WebAuthn credential id and its factor's encapsulation key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NewSecurityKey {
    pub credential_id: Vec<u8>,
    pub ek: EncapsulationKey,
}

/// S→C, for `AddSecurityKey`: an encapsulation to the new key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EnrolChallenge {
    pub ct: KemCiphertext,
}

/// C→S: the proof of possession, an enrolment-labelled tag over the new key's secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EnrolProof {
    pub tag: Tag,
}

/// S→C.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ManagementDone {
    Done(ServerOutcome),
    Refused(String),
}

/// What the server did. (The recovery codes themselves never reach it.)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ServerOutcome {
    Credentials {
        policy: SignInPolicy,
        credentials: Vec<SignInCredential>,
    },
    Added {
        id: FactorId,
    },
    Renamed,
    Removed,
    PolicySet,
    RecoveryCodesReplaced,
}
