//! What a change brings that the client makes: recovery codes, a recovery phrase, or a password
//! factor. None of it reaches the server but the keys.

use super::register::ClientRegistration;
use crate::auth::pq::kem::{EncapsulationKey, FactorKeypair};
use crate::auth::pq::messages::ManagementOp;
use crate::auth::pq::phrase::{RecoveryPhrase, RecoverySeed};
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::recovery_seed;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SignInManagementOp;
use citadel_types::crypto::SecBuffer;

/// The secrets behind a change's new keys, kept on the client until the change is done.
#[derive(Default)]
pub(super) struct NewCredentials {
    pub codes: Vec<RecoveryCode>,
    pub phrase: Option<RecoverySeed>,
    pub password: Option<ClientRegistration>,
}

/// `op` as it travels, the recovery keys `Begin` carries, and the secrets behind them.
pub(super) fn prepare(
    username: &str,
    op: SignInManagementOp,
    new_password: Option<&SecBuffer>,
) -> Result<(ManagementOp, Vec<EncapsulationKey>, NewCredentials), AccountError> {
    let mut new = NewCredentials::default();
    let mut recovery_eks = Vec::new();
    let wire = match op {
        SignInManagementOp::ListCredentials => ManagementOp::ListCredentials,
        SignInManagementOp::AddSecurityKey { label } => ManagementOp::AddSecurityKey { label },
        SignInManagementOp::RenameCredential { id, label } => {
            ManagementOp::RenameCredential { id, label }
        }
        SignInManagementOp::RemoveCredential { id } => ManagementOp::RemoveCredential { id },
        SignInManagementOp::SetSignInPolicy { policy } => ManagementOp::SetSignInPolicy { policy },
        SignInManagementOp::RegenerateRecoveryCodes => {
            new.codes = RecoveryCode::generate_set();
            for code in &new.codes {
                let keypair = FactorKeypair::derive(&recovery_seed(code))?;
                recovery_eks.push(keypair.encapsulation_key().clone());
            }
            ManagementOp::RegenerateRecoveryCodes
        }
        SignInManagementOp::RegenerateRecoveryPhrase { canonical_domain } => {
            let phrase = RecoveryPhrase::new(RecoverySeed::generate(), canonical_domain)?;
            let keypair = phrase.keypair(username)?;
            recovery_eks.push(keypair.encapsulation_key().clone());
            new.phrase = Some(phrase.seed().clone());
            ManagementOp::RegenerateRecoveryPhrase
        }
        SignInManagementOp::SetPassword => {
            let password = new_password
                .ok_or_else(|| error!(ErrorCode::PqSignInFactorMissing, "the new password"))?;
            let (start, registration) = ClientRegistration::start(username, password)?;
            new.password = Some(registration);
            ManagementOp::SetPassword {
                oprf_blinded: start.oprf_blinded,
            }
        }
    };
    Ok((wire, recovery_eks, new))
}
