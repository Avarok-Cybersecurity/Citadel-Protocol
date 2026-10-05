//! The server's side of post-quantum sign-in. Nothing here stretches a password: the server
//! evaluates the OPRF, encapsulates, and compares tags.

mod decoy;
mod login;
mod manage;
mod register;
mod settings;

pub use login::{build_login_challenge, AccountAuth, Expected, PendingLogin, VerifiedLogin};
pub use manage::{
    begin_management, Change, CommitStep, PendingEnrol, PendingManagement, MAX_CREDENTIAL_ID_BYTES,
    MAX_LABEL_CHARS,
};
pub use register::{registration_reply, PendingRegistration};
pub use settings::PqAuthServerSettings;
