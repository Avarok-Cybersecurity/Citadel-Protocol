use crate::auth::pq::admission::AdmissionToken;
use crate::auth::pq::kem::KemCiphertext;
use crate::auth::pq::proof::Tag;
use crate::auth::pq::record::KsfParams;
use citadel_types::auth::{FactorId, FactorKind};
use serde::{Deserialize, Serialize};

/// C→S: begin a login (or a step-up inside a session).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LoginStart {
    pub username: String,
    pub client_nonce: [u8; 32],
    /// `SHA3-256(password)`, blinded for the OPRF. Absent when the client has no password to
    /// offer (a key-only or recovery sign-in).
    pub oprf_blinded: Option<Vec<u8>>,
    /// Present for a recovery sign-in: the fingerprint of the encapsulation key the client's
    /// recovery code gives, so the server challenges that code alone.
    pub recovery: Option<[u8; 32]>,
    /// A fresh sign-in's admission token, when the client has one (see `auth::pq::admission`).
    pub admission: Option<AdmissionToken>,
    /// The resume token of the session the server may still hold for this client: a reconnect
    /// it recognises is not asked for admission. Checked against the held session only.
    pub resume: Option<[u8; 32]>,
}

/// S→C: the server's challenge. For an unknown username the server answers with decoys derived
/// from the username, so the reply looks the same as for a real password account.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LoginChallenge {
    pub server_nonce: [u8; 32],
    pub body: ChallengeBody,
}

/// An enum on the wire, so a new kind of challenge can be appended. Index 1 was the legacy
/// Argon2 challenge, retired with the Argon2 sunset; it must not be reused.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ChallengeBody {
    Factors(FactorChallenges),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FactorChallenges {
    /// Present when the client sent a blinded element.
    pub oprf_evaluated: Option<Vec<u8>>,
    pub salt_user: [u8; 32],
    pub prf_eval_salt: [u8; 32],
    pub ksf: KsfParams,
    pub challenges: Vec<FactorChallenge>,
}

/// One encapsulation to one of the account's factors.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FactorChallenge {
    pub factor_id: FactorId,
    pub kind: FactorKind,
    /// For a security key: its WebAuthn credential id, for `allowCredentials`.
    pub credential_id: Option<Vec<u8>>,
    pub ct: KemCiphertext,
}

/// C→S: one tag per factor the client could prove.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LoginFinish {
    pub tags: Vec<FactorTag>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FactorTag {
    pub factor_id: FactorId,
    pub tag: Tag,
}

/// C→S, carried by connect STAGE0 after a [`LoginChallenge`]. Index 1 was the legacy Argon2
/// account's upgrade, retired with the Argon2 sunset; it must not be reused.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum LoginProof {
    /// The answer to [`ChallengeBody::Factors`].
    Factors(LoginFinish),
}
