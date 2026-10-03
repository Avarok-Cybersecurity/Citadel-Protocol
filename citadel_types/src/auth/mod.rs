//! Post-quantum sign-in: the types an application, agent or UI handles.
//!
//! Every sign-in factor is an ML-KEM-1024 keypair the client derives from a seed (a password run
//! through an OPRF and Argon2id, a security key's WebAuthn PRF output, or a recovery code). The
//! server keeps only the encapsulation keys and proves each factor by encapsulating to it. The wire
//! messages that carry those proofs live in `citadel_user::auth::pq`; the types here are the ones
//! that cross into application code, so they are also exported to TypeScript.

use serde::{Deserialize, Serialize};
#[cfg(feature = "typescript")]
use ts_rs::TS;

/// The server's identifier for one enrolled factor of an account. Unique within the account and
/// never reused, so a removed factor's id cannot come to mean a different factor.
pub type FactorId = u32;

/// Which factors a sign-in must prove.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SignInPolicy {
    /// The password alone.
    Password,
    /// The password and one enrolled security key.
    PasswordAndKey,
    /// One enrolled security key, and no password.
    KeyOnly,
}

/// What a factor is derived from.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum FactorKind {
    /// The password, hardened by the server's OPRF and then Argon2id on the client.
    Password,
    /// A hardware key or passkey, through its WebAuthn PRF (`hmac-secret`) output.
    SecurityKey,
    /// A single-use recovery code.
    RecoveryCode,
}

/// One enrolled factor, as `ListCredentials` reports it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SignInCredential {
    pub id: FactorId,
    pub kind: FactorKind,
    pub label: String,
    /// The WebAuthn credential id, for a security key.
    pub credential_id: Option<Vec<u8>>,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    /// A recovery code that has been used. It can never sign in again.
    pub consumed: bool,
}

/// What a session that has signed in may do.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SessionScope {
    /// Everything the account may do.
    Full,
    /// Signed in with a recovery code: the session may enrol a security key and set the policy,
    /// and nothing else.
    Recovery,
}

/// A change to an account's sign-in factors. Each one needs a fresh proof of the account's
/// factors (a step-up), except the two a recovery session may make.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SignInManagementOp {
    ListCredentials,
    /// Enrol a security key. The client proves it holds the key's ML-KEM decapsulation key, so
    /// nobody can enrol a key they do not hold.
    AddSecurityKey {
        credential_id: Vec<u8>,
        label: String,
    },
    RenameCredential {
        id: FactorId,
        label: String,
    },
    /// Refused if the account's policy could no longer be satisfied without it.
    RemoveCredential {
        id: FactorId,
    },
    /// Refused if the account's factors cannot satisfy the new policy.
    SetSignInPolicy {
        policy: SignInPolicy,
    },
    /// Replaces every recovery code, used or not.
    RegenerateRecoveryCodes,
}

impl SignInManagementOp {
    /// Whether a session signed in with a recovery code may make this change.
    pub fn allowed_in_recovery(&self) -> bool {
        matches!(
            self,
            Self::AddSecurityKey { .. } | Self::SetSignInPolicy { .. }
        )
    }
}

/// What a [`SignInManagementOp`] that the server carried out returns to the application.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SignInManagementOutcome {
    Credentials(Vec<SignInCredential>),
    Added {
        id: FactorId,
    },
    Renamed,
    Removed,
    PolicySet,
    /// The new codes, formatted for display. The client generated them and the server only ever
    /// saw their keys, so this is the one time they can be shown.
    RecoveryCodes(Vec<String>),
}
