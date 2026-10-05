use super::ksf::{password_input, password_keypair};
use crate::auth::pq::kem::FactorKeypair;
use crate::auth::pq::messages::{RegFinish, RegReply, RegStart};
use crate::auth::pq::oprf::{self, OprfClientState};
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::recovery_seed;
use crate::misc::AccountError;
use citadel_types::crypto::SecBuffer;
use zeroize::Zeroizing;

/// A registration between [`RegStart`] and [`RegFinish`].
pub struct ClientRegistration {
    input: Zeroizing<[u8; 32]>,
    oprf: OprfClientState,
}

impl ClientRegistration {
    pub fn start(username: &str, password: &SecBuffer) -> Result<(RegStart, Self), AccountError> {
        let input = password_input(password);
        let (oprf, oprf_blinded) = oprf::client_blind(input.as_ref())?;
        let start = RegStart {
            username: username.to_string(),
            oprf_blinded,
            // Set by the registration that sends this.
            admission: None,
        };
        Ok((start, Self { input, oprf }))
    }

    /// The factors' keys, and the recovery codes behind them (empty unless asked for). The codes
    /// must be shown to the user now: nothing else ever holds them.
    pub async fn finish(
        self,
        reply: &RegReply,
        with_recovery_codes: bool,
    ) -> Result<(RegFinish, Vec<RecoveryCode>), AccountError> {
        let password = password_keypair(
            &self.input,
            &self.oprf,
            &reply.oprf_evaluated,
            &reply.salt_user,
            reply.ksf,
        )
        .await?;
        let codes = if with_recovery_codes {
            RecoveryCode::generate_set()
        } else {
            Vec::new()
        };
        let recovery_eks = codes
            .iter()
            .map(|code| {
                FactorKeypair::derive(&recovery_seed(code)).map(|kp| kp.encapsulation_key().clone())
            })
            .collect::<Result<_, _>>()?;
        let finish = RegFinish {
            password_ek: password.encapsulation_key().clone(),
            recovery_eks,
        };
        Ok((finish, codes))
    }
}
