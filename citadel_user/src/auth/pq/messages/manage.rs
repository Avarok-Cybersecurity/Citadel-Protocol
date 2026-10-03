use super::login::{LoginChallenge, LoginFinish, LoginStart};
use crate::auth::pq::kem::{EncapsulationKey, KemCiphertext};
use crate::auth::pq::proof::Tag;
use citadel_types::auth::{FactorId, SignInCredential, SignInManagementOp};
use serde::{Deserialize, Serialize};

/// The management exchange, in an authenticated session:
/// `Begin` → `Challenge` → `Commit` → (`EnrolChallenge` → `EnrolProof`, to add a key) → `Done`.
///
/// The step-up is a login challenge bound to the operation, so a proof made for one change cannot
/// authorize another. A key being added is proven separately, after the step-up, because the
/// client can only derive it once the challenge has told it the account's PRF salt.
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
}

/// C→S. The step-up tags are bound to `Begin`, `Challenge` and `new_key_ek` together.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCommit {
    pub step_up: LoginFinish,
    /// `AddSecurityKey`: the new key's encapsulation key.
    pub new_key_ek: Option<EncapsulationKey>,
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
    Credentials(Vec<SignInCredential>),
    Added { id: FactorId },
    Renamed,
    Removed,
    PolicySet,
    RecoveryCodesReplaced,
}
