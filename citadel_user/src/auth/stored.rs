//! The form a [`DeclaredAuthenticationMode`] is stored in.
//!
//! [`StoredAuthMode`] is append-only: a variant's index is what bincode writes, so it is the
//! record's version on disk, and reordering or removing a variant would make every later record
//! read as a different kind. A new kind of record is a new variant at the end, reached through
//! [`super::migration`].
//!
//! Version 0 is the Argon2 record of the accounts that predate post-quantum sign-in. Its
//! verifier is gone, so it is kept only to be read and refused:
//! - a **server** record is refused at load, with [`ErrorCode::AuthRecordRetired`], because
//!   nothing can sign it in any more;
//! - a **client** record held nothing a post-quantum sign-in uses (the client rederives every
//!   factor), so it loads as the post-quantum client record it is equivalent to.

use super::{DeclaredAuthenticationMode, PqAuthSide};
use citadel_io::ErrorCode;
use serde::{Deserialize, Serialize};

/// The version [`StoredAuthMode::Transient`] is written as.
pub const TRANSIENT_VERSION: u32 = 1;
/// The version [`StoredAuthMode::PostQuantum`] is written as.
pub const POST_QUANTUM_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
pub enum StoredAuthMode {
    /// Version 0, retired. Read, never written.
    RetiredArgon {
        username: String,
        full_name: String,
        argon: RetiredArgonContainer,
    },
    Transient {
        username: String,
        full_name: String,
    },
    PostQuantum {
        username: String,
        full_name: String,
        side: PqAuthSide,
    },
}

/// The shape of the Argon2 container a version-0 record carried, field for field, so the record
/// still parses without the Argon2 crate.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum RetiredArgonContainer {
    Client {
        settings: RetiredArgonSettings,
    },
    Server {
        settings: RetiredArgonSettings,
        hashed_password: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RetiredArgonSettings {
    inner: RetiredArgonSettingsInner,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct RetiredArgonSettingsInner {
    ad: Vec<u8>,
    salt: Vec<u8>,
    lanes: u32,
    hash_length: u32,
    mem_cost: u32,
    time_cost: u32,
    secret: Vec<u8>,
}

impl From<DeclaredAuthenticationMode> for StoredAuthMode {
    fn from(mode: DeclaredAuthenticationMode) -> Self {
        match mode {
            DeclaredAuthenticationMode::Transient {
                username,
                full_name,
            } => Self::Transient {
                username,
                full_name,
            },
            DeclaredAuthenticationMode::PostQuantum {
                username,
                full_name,
                side,
            } => Self::PostQuantum {
                username,
                full_name,
                side,
            },
        }
    }
}

impl TryFrom<StoredAuthMode> for DeclaredAuthenticationMode {
    type Error = String;

    fn try_from(stored: StoredAuthMode) -> Result<Self, Self::Error> {
        match stored {
            StoredAuthMode::RetiredArgon {
                username,
                full_name,
                argon: RetiredArgonContainer::Client { .. },
            } => Ok(Self::PostQuantum {
                username,
                full_name,
                side: PqAuthSide::Client,
            }),
            StoredAuthMode::RetiredArgon {
                username,
                argon: RetiredArgonContainer::Server { .. },
                ..
            } => Err(citadel_io::error!(ErrorCode::AuthRecordRetired, username).into_string()),
            StoredAuthMode::Transient {
                username,
                full_name,
            } => Ok(Self::Transient {
                username,
                full_name,
            }),
            StoredAuthMode::PostQuantum {
                username,
                full_name,
                side,
            } => Ok(Self::PostQuantum {
                username,
                full_name,
                side,
            }),
        }
    }
}

#[cfg(test)]
#[path = "stored_tests.rs"]
mod tests;
