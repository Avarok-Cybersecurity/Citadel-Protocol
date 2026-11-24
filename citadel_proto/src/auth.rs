//! Authentication Request Types for Citadel Protocol
//!
//! This module defines the authentication request types and structures used for establishing
//! connections in the Citadel Protocol. It supports both credential-based authentication and
//! transient accounts.
//!
//! # Features
//! - **Credential Authentication**: Username/password-based authentication
//! - **Transient accounts**: a session with its own CID that the server never persists and that
//!   has no password (a server may disallow them: `NodeBuilder::with_transient_accounts`)
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
//! // A transient account
//! let server_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//! let uuid = Uuid::new_v4();
//! let transient_auth = AuthenticationRequest::transient(uuid, server_addr);
//! ```
//!
//! # Important Notes
//! - Passwords are always handled using SecBuffer for secure memory management
//! - Transient connections use device-specific cryptographic bundles
//! - CID extraction is only available for credential-based authentication
//! - Server addresses are required for a transient account
//!
//! # Related Components
//! - `citadel_types::crypto::SecBuffer`: Secure credential storage
//! - `citadel_types::user::UserIdentifier`: User identification types
//! - `proto::packet_processor::connect_packet`: Connection handling
//! - `proto::validation`: Authentication validation
//!

#[cfg(feature = "security-key")]
pub use crate::proto::pq_sign_in::security_key::SecurityKey;
#[cfg(all(feature = "security-key", not(target_family = "wasm")))]
pub use crate::proto::pq_sign_in::security_key::SecurityKeyPrompt;
pub use crate::proto::pq_sign_in::security_key::{
    security_key_channel, SecurityKeyChallenge, SecurityKeyPrf, SecurityKeyPurpose,
    KEY_PRESENCE_WINDOW,
};
use citadel_types::crypto::SecBuffer;
use citadel_types::user::UserIdentifier;
pub use citadel_user::auth::pq::client::{SecurityKeyCeremony, SecurityKeyRequest};
use citadel_user::auth::pq::phrase::RecoveryPhrase;
use citadel_user::auth::pq::resume::ResumeCredential;
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
    /// the application's [`SecurityKeyPrf`] channel), or the recovery phrase. Which ones the
    /// account needs is its policy. Never serialized: the key channel cannot cross a wire.
    SignIn {
        id: UserIdentifier,
        #[serde(skip)]
        factors: SignInFactors,
    },
    /// A transient account: a session with its own CID that the server never persists and that
    /// has no password. A server that disallows them refuses with
    /// `ErrorCode::PasswordlessUnsupported`.
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

    /// A transient account (see [`Self::Passwordless`]): no credentials, only a one-time
    /// device-dependent cryptographic bundle. `uuid` is the identifier the client proposes.
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
    /// The recovery phrase, as this server knows it. A sign-in with it is a recovery sign-in:
    /// the session may only manage the account's credentials.
    pub recovery_phrase: Option<RecoveryPhrase>,
    /// The admission token (a Turnstile response) for a server that asks fresh sign-ins for one.
    /// Sent only inside the post-quantum channel, and never printed.
    pub admission: Option<String>,
    /// A resume credential from an earlier sign-in, offered in place of every factor above. One
    /// past its expiry is refused before anything is sent, as `ResumeCredentialExpired`.
    pub resume: Option<ResumeCredential>,
    /// Asks a full sign-in for a resume credential living this many seconds. The server grants
    /// no more than its own maximum; `None` asks for none.
    pub resume_lifetime_s: Option<u64>,
}

impl SignInFactors {
    /// Signs in again with `credential`, and nothing else.
    pub fn resume(credential: ResumeCredential) -> Self {
        Self {
            resume: Some(credential),
            ..Default::default()
        }
    }

    pub fn with_resume_lifetime(mut self, lifetime: std::time::Duration) -> Self {
        self.resume_lifetime_s = Some(lifetime.as_secs());
        self
    }

    pub fn password<T: Into<SecBuffer>>(password: T) -> Self {
        Self {
            password: Some(password.into()),
            ..Default::default()
        }
    }

    pub fn with_admission(mut self, token: impl Into<String>) -> Self {
        self.admission = Some(token.into());
        self
    }

    pub fn with_security_key(mut self, security_key: SecurityKeyPrf) -> Self {
        self.security_key = Some(security_key);
        self
    }

    /// A recovery sign-in with the account's phrase, bound to the server's canonical domain.
    pub fn recovery_phrase(phrase: RecoveryPhrase) -> Self {
        Self {
            recovery_phrase: Some(phrase),
            ..Default::default()
        }
    }
}

impl std::fmt::Debug for SignInFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignInFactors")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("security_key", &self.security_key.is_some())
            .field(
                "recovery_phrase",
                &self.recovery_phrase.as_ref().map(|_| "***"),
            )
            .field("admission", &self.admission.as_ref().map(|_| "***"))
            .field("resume", &self.resume)
            .field("resume_lifetime_s", &self.resume_lifetime_s)
            .finish()
    }
}
