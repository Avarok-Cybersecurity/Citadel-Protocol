//! The change a management exchange makes, as it travels.

use citadel_types::auth::{FactorId, RecoveryCodesRetired, SignInPolicy};
use serde::{Deserialize, Serialize};

/// A change on the wire: `SignInManagementOp` as it travels.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ManagementOp {
    ListCredentials,
    RenameCredential {
        id: FactorId,
        label: String,
    },
    RemoveCredential {
        id: FactorId,
    },
    SetSignInPolicy {
        policy: SignInPolicy,
    },
    /// Retired: regenerating recovery codes. Its slot keeps the later changes' encoding, and
    /// reading it is refused.
    #[doc(hidden)]
    #[serde(rename = "RegenerateRecoveryCodes")]
    RetiredRegenerateRecoveryCodes(RecoveryCodesRetired),
    /// The client creates the credential once the challenge has named the relying party.
    AddSecurityKey {
        label: String,
    },
    /// The new password's `SHA3-256`, blinded for the OPRF. The server answers with the
    /// evaluation and a fresh salt (`ManagementCeremony::password`); the client sends the new
    /// factor's key in `CommitCeremony::password_ek`.
    SetPassword {
        oprf_blinded: Vec<u8>,
    },
    /// The new phrase's key rides in `ManagementBegin::recovery_eks`.
    RegenerateRecoveryPhrase,
}

impl ManagementOp {
    /// Whether a recovery session may make this change (see
    /// `SignInManagementOp::allowed_in_recovery`, which this mirrors on the wire).
    pub fn allowed_in_recovery(&self) -> bool {
        matches!(
            self,
            Self::ListCredentials
                | Self::AddSecurityKey { .. }
                | Self::RemoveCredential { .. }
                | Self::SetSignInPolicy { .. }
                | Self::SetPassword { .. }
                | Self::RegenerateRecoveryPhrase
        )
    }

    /// How many recovery keys `ManagementBegin::recovery_eks` carries for this change.
    pub fn recovery_key_count(&self) -> usize {
        match self {
            Self::RegenerateRecoveryPhrase => 1,
            _ => 0,
        }
    }
}
