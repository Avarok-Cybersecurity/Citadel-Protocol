//! The post-quantum sign-in messages. All of them travel inside the session's post-quantum
//! channel; none is ever sent in the clear.
//!
//! - Registration: [`RegStart`] → [`RegStartReply`] → [`RegFinish`].
//! - Login: [`LoginStart`] → [`LoginChallenge`] → [`LoginProof`].
//! - Management, in an authenticated session: [`ManagementMessage`].
//! - Recovery, on a device with no bundle: [`RecoverStart`] → [`AuthChallenge`] →
//!   [`RecoverProof`] → [`RecoverDone`].

mod login;
mod manage;
mod manage_op;
mod recover;
mod register;

pub use login::{
    AuthChallenge, ChallengeBody, ChallengeCeremony, FactorChallenge, FactorChallenges, FactorTag,
    LoginChallenge, LoginFinish, LoginProof, LoginStart,
};
pub(crate) use manage::key_binding;
pub use manage::{
    CommitCeremony, EnrolChallenge, EnrolProof, ManagementBegin, ManagementCeremony,
    ManagementChallenge, ManagementCommit, ManagementDone, ManagementMessage, ManagementOp,
    NewSecurityKey, ServerOutcome,
};
pub use recover::{DeviceOffer, RecoverDone, RecoverProof, RecoverStart};
pub use register::{RegFinish, RegReply, RegStart, RegStartReply};

/// The serialization both sides hash into a transcript. bincode is deterministic, so the two
/// sides hash the same bytes for the same message.
pub(crate) fn transcript_bytes<T: serde::Serialize>(message: &T) -> Vec<u8> {
    bincode::serialize(message).expect("sign-in messages always serialize")
}
