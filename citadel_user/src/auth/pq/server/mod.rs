//! The server's side of post-quantum sign-in. Nothing here stretches a password: the server
//! evaluates the OPRF, encapsulates, and compares tags.

mod change;
mod decoy;
mod enrol;
mod login;
mod manage;
mod register;
mod resume;
mod settings;
mod verify;

pub use change::Change;
pub use login::{
    build_login_challenge, build_recovery_challenge, AccountAuth, Expectation, Expected,
    PendingLogin, VerifiedLogin,
};
pub use manage::{
    begin_management, CommitStep, PendingEnrol, PendingManagement, MAX_CREDENTIAL_ID_BYTES,
    MAX_LABEL_CHARS,
};
pub use register::{registration_reply, PendingRegistration};
#[cfg(test)]
pub(crate) use resume::issue_grant;
pub use resume::{build_resume_challenge, grant_after, reissue_grant};
pub use settings::PqAuthServerSettings;
