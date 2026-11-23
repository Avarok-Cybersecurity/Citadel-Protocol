use super::login::{LoginChallenge, LoginFinish, LoginStart};
pub use super::manage_op::ManagementOp;
use super::register::RegReply;
use super::transcript_bytes;
use crate::auth::pq::kem::{EncapsulationKey, KemCiphertext};
use crate::auth::pq::proof::Tag;
use crate::auth::pq::resume::{PresentedResume, ResumeGrant};
use citadel_types::auth::{FactorId, RecoveryCodesRetired, SignInCredential, SignInPolicy};
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
    /// `RegenerateRecoveryPhrase`: the new phrase's key, alone.
    pub recovery_eks: Vec<EncapsulationKey>,
}

/// S→C.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementChallenge {
    pub step_up: LoginChallenge,
    pub ceremony: ManagementCeremony,
}

/// What a management challenge tells the client about the change's keys.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCeremony {
    /// The relying party the step-up's keys, and a key being added, are scoped to.
    pub rp_id: Option<String>,
    /// `AddSecurityKey`: the credential ids of the account's keys. The new credential is not
    /// created on an authenticator that holds one of them, so no key is enrolled twice.
    pub exclude_credentials: Vec<Vec<u8>>,
    /// `SetPassword`: the new password's OPRF evaluation and the fresh salt and parameters its
    /// factor is stretched with.
    pub password: Option<RegReply>,
}

/// C→S. The step-up tags are bound to `Begin`, `Challenge` and the key being added together.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagementCommit {
    pub step_up: LoginFinish,
    pub ceremony: CommitCeremony,
}

/// The keys a change brings, which the commit's transcript binds.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommitCeremony {
    /// `AddSecurityKey`: the key the client created.
    pub new_key: Option<NewSecurityKey>,
    /// `SetPassword`: the new password factor's key.
    pub password_ek: Option<EncapsulationKey>,
    /// The resume credential this session's device holds, for the server to bind to the account
    /// as the change leaves it (see `auth::pq::resume`).
    pub resume: Option<PresentedResume>,
}

impl ManagementCommit {
    /// The bytes of the keys this commit adds, as its transcript binds them.
    pub fn key_binding(&self) -> Vec<u8> {
        key_binding(&self.ceremony)
    }
}

/// The created key with its credential id, and a new password's key.
pub(crate) fn key_binding(ceremony: &CommitCeremony) -> Vec<u8> {
    transcript_bytes(ceremony)
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
    /// Done, and the session's resume credential re-bound to the account as it now stands.
    Reissued {
        outcome: ServerOutcome,
        grant: ResumeGrant,
    },
}

/// What the server did. (A new recovery phrase itself never reaches it.)
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
    /// Retired: recovery codes replaced. Its slot keeps the later outcomes' encoding, and
    /// reading it is refused.
    #[doc(hidden)]
    #[serde(rename = "RecoveryCodesReplaced")]
    RetiredRecoveryCodesReplaced(RecoveryCodesRetired),
    PasswordSet,
    RecoveryPhraseReplaced,
}
