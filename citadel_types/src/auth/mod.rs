//! Post-quantum sign-in: the types an application, agent or UI handles.
//!
//! Every sign-in factor is an ML-KEM-1024 keypair the client derives from a seed (a password run
//! through an OPRF and Argon2id, a security key's WebAuthn PRF output, or the recovery phrase). The
//! server keeps only the encapsulation keys and proves each factor by encapsulating to it. The wire
//! messages that carry those proofs live in `citadel_user::auth::pq`; the types here are the ones
//! that cross into application code, so they are also exported to TypeScript.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "typescript")]
use ts_rs::TS;

#[cfg(test)]
mod tests;

/// The server's identifier for one enrolled factor of an account. Unique within the account and
/// never reused, so a removed factor's id cannot come to mean a different factor.
pub type FactorId = u32;

/// Why a retired recovery-code variant is refused when read.
pub const RECOVERY_CODES_RETIRED: &str =
    "recovery codes are retired; the recovery phrase replaces them";

/// Holds the place of a retired recovery-code variant, so the variants after it keep their
/// encoding. Nothing can construct one, and reading one is refused with
/// [`RECOVERY_CODES_RETIRED`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryCodesRetired {}

impl Serialize for RecoveryCodesRetired {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        match *self {}
    }
}

impl<'de> Deserialize<'de> for RecoveryCodesRetired {
    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(RECOVERY_CODES_RETIRED))
    }
}

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
    /// Retired: a recovery code. Its slot keeps the recovery phrase's encoding.
    #[doc(hidden)]
    #[serde(rename = "RecoveryCode")]
    #[cfg_attr(feature = "typescript", ts(skip))]
    RetiredRecoveryCode(RecoveryCodesRetired),
    /// The account's recovery phrase: 24 words for a 32-byte seed, bound to one server and one
    /// username. Reusable; an account has at most one.
    RecoveryPhrase,
    /// A device's resume key: proven in place of the account's factors by a device holding a
    /// resume credential. Never enrolled: the server keeps no record of one.
    ResumeKey,
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
    /// A factor that can never sign in again. No current kind is consumed by use.
    pub consumed: bool,
}

/// What a session that has signed in may do.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SessionScope {
    /// Everything the account may do.
    Full,
    /// The recovery console: signed in with the recovery phrase, the session
    /// may manage the account's credentials (see [`SignInManagementOp::allowed_in_recovery`]) and
    /// nothing else. An application shows it as a guided set of credential steps, not its
    /// ordinary interface.
    Recovery,
}

/// A change to an account's sign-in factors. Each one needs a fresh proof of the account's
/// factors (a step-up), except in a recovery session, which proves nothing again and may make only
/// the changes [`Self::allowed_in_recovery`] names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SignInManagementOp {
    ListCredentials,
    /// Enrol a security key. The client creates the key's credential, then proves it holds the
    /// key's ML-KEM decapsulation key, so nobody can enrol a key they do not hold.
    AddSecurityKey {
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
    /// Retired: regenerating recovery codes. Its slot keeps the later changes' encoding.
    #[doc(hidden)]
    #[serde(rename = "RegenerateRecoveryCodes")]
    #[cfg_attr(feature = "typescript", ts(skip))]
    RetiredRegenerateRecoveryCodes(RecoveryCodesRetired),
    /// Sets the account's password: a forgotten one from a recovery session, or a change from a
    /// full one. The new password itself never reaches the server; the client turns it into a
    /// fresh password factor, which replaces the old one.
    SetPassword,
    /// Replaces the recovery phrase with a new one the client draws.
    /// The old phrase stops working at once. `canonical_domain` is the server's canonical domain,
    /// which the phrase's factor is bound to (the caller canonicalises it).
    RegenerateRecoveryPhrase {
        canonical_domain: String,
    },
}

impl SignInManagementOp {
    /// Whether a recovery session may make this change. Such a session manages credentials and
    /// nothing else: it lists them, sets the password, replaces the phrase, enrols or removes a
    /// security key, and sets the policy (a lost key's way back in).
    pub fn allowed_in_recovery(&self) -> bool {
        matches!(
            self,
            Self::ListCredentials
                | Self::AddSecurityKey { .. }
                | Self::RemoveCredential { .. }
                | Self::SetSignInPolicy { .. }
                | Self::SetPassword
                | Self::RegenerateRecoveryPhrase { .. }
        )
    }
}

/// What a [`SignInManagementOp`] that the server carried out returns to the application.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum SignInManagementOutcome {
    /// The account's factors, and the policy that decides which of them a sign-in must prove.
    Credentials {
        policy: SignInPolicy,
        credentials: Vec<SignInCredential>,
    },
    Added {
        id: FactorId,
    },
    Renamed,
    Removed,
    PolicySet,
    /// Retired: new recovery codes. Its slot keeps the later outcomes' encoding.
    #[doc(hidden)]
    #[serde(rename = "RecoveryCodes")]
    #[cfg_attr(feature = "typescript", ts(skip))]
    RetiredRecoveryCodes(RecoveryCodesRetired),
    PasswordSet,
    /// The new recovery phrase's 24 words. The client drew them and the server only ever saw
    /// their key, so this is the one time they exist anywhere but with the user.
    RecoveryPhrase(Vec<String>),
}
