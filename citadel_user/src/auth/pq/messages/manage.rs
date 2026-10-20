use super::login::{LoginChallenge, LoginFinish, LoginStart};
use crate::auth::pq::kem::{EncapsulationKey, KemCiphertext};
use crate::auth::pq::proof::Tag;
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
    pub op: SignInManagementOp,
    /// The step-up. A recovery session sends one too; the server challenges no factor in it.
    pub step_up: LoginStart,
    /// `RegenerateRecoveryCodes`: the new codes' keys.
    pub recovery_eks: Vec<EncapsulationKey>,
}

/// S→C.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementChallenge {
    pub step_up: LoginChallenge,
    /// `AddSecurityKey`: the credential ids of the account's keys. The new credential is not
    /// created on an authenticator that holds one of them, so no key is enrolled twice.
    pub exclude_credentials: Vec<Vec<u8>>,
}

/// C→S. The step-up tags are bound to `Begin`, `Challenge` and `new_key` together.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCommit {
    pub step_up: LoginFinish,
    /// `AddSecurityKey`: the key the client created.
    pub new_key: Option<NewSecurityKey>,
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
