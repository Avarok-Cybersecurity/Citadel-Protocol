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
    AuthChallenge, ChallengeBody, ChallengeCeremony, FactorChallenge, FactorChallenges, FactorTag,
    LoginChallenge, LoginFinish, LoginProof, LoginStart,
};
pub(crate) use manage::key_binding;
pub use manage::{
    CommitCeremony, EnrolChallenge, EnrolProof, ManagementBegin, ManagementCeremony,
    ManagementChallenge, ManagementCommit, ManagementDone, ManagementMessage, ManagementOp,
    NewSecurityKey, ServerOutcome,
};
pub use register::{RegFinish, RegReply, RegStart, RegStartReply};

/// Which layout of the sign-in messages a peer reads. Every message is 0.12.2's; the security-key
/// ceremony's fields ride appended after it ([`AuthChallenge`], [`ManagementChallenge`],
/// [`ManagementCommit`]), sent only to a peer that reads them, so a 0.12.2 peer is sent, and
/// hashes, exactly the bytes it always did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignInLayout {
    V0_12_2,
    SecurityKeyCeremony,
}

/// The serialization both sides hash into a transcript. bincode is deterministic, so the two
/// sides hash the same bytes for the same message.
pub(crate) fn transcript_bytes<T: serde::Serialize>(message: &T) -> Vec<u8> {
    bincode::serialize(message).expect("sign-in messages always serialize")
}
