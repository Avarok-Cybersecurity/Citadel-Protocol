use crate::auth::pq::kem::EncapsulationKey;
use crate::auth::pq::record::KsfParams;
use serde::{Deserialize, Serialize};

/// C→S: begin a post-quantum registration. The password factor is always enrolled; security keys
/// are added afterwards, with a proof of possession, through `AddSecurityKey`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RegStart {
    pub username: String,
    /// `SHA3-256(password)`, blinded for the OPRF.
    pub oprf_blinded: Vec<u8>,
}

/// S→C: what the client needs to derive its password factor.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RegReply {
    pub oprf_evaluated: Vec<u8>,
    pub salt_user: [u8; 32],
    /// The salt the account's security keys are evaluated with (the WebAuthn PRF `eval` input).
    pub prf_eval_salt: [u8; 32],
    pub ksf: KsfParams,
}

/// S→C: the answer to [`RegStart`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RegStartReply {
    Accepted(RegReply),
    /// This server has no OPRF seed configured. The client registers with the legacy path.
    Unsupported,
}

/// C→S: the factors' encapsulation keys. The server stores them; nothing here lets anyone check a
/// password guess without the OPRF seed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RegFinish {
    pub password_ek: EncapsulationKey,
    /// One key per recovery code. Empty when the account upgrades from a legacy record: the user
    /// generates codes from settings afterwards.
    pub recovery_eks: Vec<EncapsulationKey>,
}
