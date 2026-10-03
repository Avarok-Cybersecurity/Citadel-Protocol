//! The post-quantum sign-in messages. All of them travel inside the session's post-quantum
//! channel; none is ever sent in the clear.
//!
//! - Registration: [`RegStart`] → [`RegStartReply`] → [`RegFinish`].
//! - Login: [`LoginStart`] → [`LoginChallenge`] → [`LoginProof`].
//! - Management, in an authenticated session: [`ManagementMessage`].

mod login;
mod manage;
mod register;

pub use login::{
    ChallengeBody, FactorChallenge, FactorChallenges, FactorTag, LoginChallenge, LoginFinish,
    LoginProof, LoginStart,
};
pub use manage::{
    EnrolChallenge, EnrolProof, ManagementBegin, ManagementChallenge, ManagementCommit,
    ManagementDone, ManagementMessage, ServerOutcome,
};
pub use register::{RegFinish, RegReply, RegStart, RegStartReply};

/// The serialization both sides hash into a transcript. bincode is deterministic, so the two
/// sides hash the same bytes for the same message.
pub(crate) fn transcript_bytes<T: serde::Serialize>(message: &T) -> Vec<u8> {
    bincode::serialize(message).expect("sign-in messages always serialize")
}
