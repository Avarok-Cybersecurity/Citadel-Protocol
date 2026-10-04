//! Authentication Mode Management
//!
//! What a Citadel Network Account (CNAC) keeps about how it signs in: a transient (passwordless)
//! identity, or post-quantum factors (see [`pq`]).
//!
//! # Records are versioned, and migrate forward
//!
//! The stored form is [`stored::StoredAuthMode`], an append-only enum whose variant index is the
//! record's version. [`migration`] is the one way a record changes version: one-way, one record
//! at a time, at the moment the account proves itself. Version 0, the Argon2 record, is retired:
//! its verifier is gone, and it is read only to be refused or, on a client, mapped (see
//! [`stored`]).
//!
//! # Related Components
//!
//! * `proposed_credentials` - The names a login or registration carries
//! * `ClientNetworkAccount` - Holds the authentication mode
//! * `AccountManager` - Creates and changes accounts

#![allow(missing_docs, dead_code)]
use pq::record::PqAuthRecord;
use serde::{Deserialize, Serialize};

/// For handling misc requirements
pub mod proposed_credentials;

/// Post-quantum sign-in: ML-KEM factors, the OPRF-hardened password, and their management.
pub mod pq;

/// The auth-migration pattern: how a stored record moves from one version to the next.
pub mod migration;

/// The versioned form an authentication mode is stored in.
pub mod stored;

/// For storing data inside the CNACs. Both need unique usernames b/c of the unique username
/// requirement on the SQL backend. Stored as [`stored::StoredAuthMode`], whose variant order is
/// the on-disk version order: never reorder or remove one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(into = "stored::StoredAuthMode", try_from = "stored::StoredAuthMode")]
pub enum DeclaredAuthenticationMode {
    Transient {
        username: String,
        full_name: String,
    },
    /// Signs in with post-quantum factors (see [`pq`]).
    PostQuantum {
        username: String,
        full_name: String,
        side: PqAuthSide,
    },
}

/// What each side of a post-quantum account keeps. The client keeps nothing secret: every factor
/// is rederived at sign-in.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PqAuthSide {
    Client,
    Server(Box<PqAuthRecord>),
}

impl DeclaredAuthenticationMode {
    pub fn username(&self) -> &str {
        match self {
            Self::Transient { username, .. } => username.as_str(),
            Self::PostQuantum { username, .. } => username.as_str(),
        }
    }

    pub fn full_name(&self) -> &str {
        match self {
            Self::Transient { full_name, .. } => full_name.as_str(),
            Self::PostQuantum { full_name, .. } => full_name.as_str(),
        }
    }

    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }

    /// The server's post-quantum record, if this is one.
    pub fn pq_record(&self) -> Option<&PqAuthRecord> {
        match self {
            Self::PostQuantum {
                side: PqAuthSide::Server(record),
                ..
            } => Some(record),
            _ => None,
        }
    }
}
