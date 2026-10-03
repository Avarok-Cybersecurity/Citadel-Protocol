//! Authentication Request Types for Citadel Protocol
//!
//! This module defines the authentication request types and structures used for establishing
//! connections in the Citadel Protocol. It supports both credential-based and passwordless
//! authentication methods.
//!
//! # Features
//! - **Credential Authentication**: Username/password-based authentication
//! - **Passwordless Authentication**: Device-based transient connections
//! - **Secure Credential Handling**: Uses SecBuffer for password protection
//! - **User Identification**: Supports both CID and username-based identification
//! - **Server Address Management**: Handles server connection information
//!
//! # Usage Example
//! ```rust
//! use citadel_proto::auth::AuthenticationRequest;
//! use citadel_types::user::UserIdentifier;
//! use citadel_types::crypto::SecBuffer;
//! use std::net::SocketAddr;
//! use uuid::Uuid;
//!
//! // Credential-based authentication
//! let cred_auth = AuthenticationRequest::credentialed(
//!     UserIdentifier::from("username"),
//!     SecBuffer::from("password")
//! );
//!
//! // Passwordless authentication
//! let server_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//! let uuid = Uuid::new_v4();
//! let transient_auth = AuthenticationRequest::transient(uuid, server_addr);
//! ```
//!
//! # Important Notes
//! - Passwords are always handled using SecBuffer for secure memory management
//! - Transient connections use device-specific cryptographic bundles
//! - CID extraction is only available for credential-based authentication
//! - Server addresses are required for passwordless authentication
//!
//! # Related Components
//! - `citadel_types::crypto::SecBuffer`: Secure credential storage
//! - `citadel_types::user::UserIdentifier`: User identification types
//! - `proto::packet_processor::connect_packet`: Connection handling
//! - `proto::validation`: Authentication validation
//!

pub use crate::proto::pq_sign_in::security_key::{
    security_key_channel, SecurityKeyChallenge, SecurityKeyPrf, SecurityKeyPurpose,
    KEY_PRESENCE_WINDOW,
};
use citadel_types::crypto::SecBuffer;
use citadel_types::user::UserIdentifier;
pub use citadel_user::auth::pq::client::SecurityKeyRequest;
use citadel_user::auth::pq::recovery::RecoveryCode;
use citadel_user::misc::AccountError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// Arguments for connecting to a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationRequest {
    /// Credentials used for the connection
    Credentialed {
        id: UserIdentifier,
        password: SecBuffer,
    },
    /// Post-quantum sign-in with any combination of factors: a password, a security key (through
    /// the application's [`SecurityKeyPrf`] channel), or a single-use recovery code. Which ones the
    /// account needs is its policy. Never serialized: the key channel cannot cross a wire.
    SignIn {
        id: UserIdentifier,
        #[serde(skip)]
        factors: SignInFactors,
    },
    /// No credentials/one-time connection
    Passwordless {
        username: String,
        server_addr: SocketAddr,
    },
}

impl AuthenticationRequest {
    /// Credentials used for connecting (registration implied to have occurred)
    pub fn credentialed<T: Into<UserIdentifier>, V: Into<SecBuffer>>(id: T, password: V) -> Self {
        Self::Credentialed {
            id: id.into(),
            password: password.into(),
        }
    }

    /// No credentials will be used for login, only a one-time device-dependent cryptographic bundle
    pub fn transient(uuid: Uuid, server_addr: SocketAddr) -> Self {
        Self::Passwordless {
            username: uuid.to_string(),
            server_addr,
        }
    }

    /// Post-quantum sign-in with `factors` (see [`SignInFactors`]).
    pub fn sign_in<T: Into<UserIdentifier>>(id: T, factors: SignInFactors) -> Self {
        Self::SignIn {
            id: id.into(),
            factors,
        }
    }

    pub fn session_cid(&self) -> Option<u64> {
        match self {
            AuthenticationRequest::Credentialed { id, .. }
            | AuthenticationRequest::SignIn { id, .. } => {
                if let UserIdentifier::ID(cid) = id {
                    Some(*cid)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// The factors a post-quantum sign-in (or a management step-up) offers. Offer what the user gave;
/// the account's policy decides what suffices, and the server never says which was wrong.
#[derive(Clone, Default)]
pub struct SignInFactors {
    pub password: Option<SecBuffer>,
    /// Where to ask for a security-key touch, if the challenge names keys.
    pub security_key: Option<SecurityKeyPrf>,
    /// A recovery code. A sign-in with one is a recovery sign-in: it spends the code, and the
    /// session may only enrol a security key and set the policy.
    pub recovery_code: Option<RecoveryCode>,
}

impl SignInFactors {
    pub fn password<T: Into<SecBuffer>>(password: T) -> Self {
        Self {
            password: Some(password.into()),
            ..Default::default()
        }
    }

    pub fn with_security_key(mut self, security_key: SecurityKeyPrf) -> Self {
        self.security_key = Some(security_key);
        self
    }

    /// Reads a typed recovery code (see `RecoveryCode::parse`).
    pub fn recovery_code(typed: &str) -> Result<Self, AccountError> {
        Ok(Self {
            recovery_code: Some(RecoveryCode::parse(typed)?),
            ..Default::default()
        })
    }
}

impl std::fmt::Debug for SignInFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignInFactors")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("security_key", &self.security_key.is_some())
            .field("recovery_code", &self.recovery_code.as_ref().map(|_| "***"))
            .finish()
    }
}
