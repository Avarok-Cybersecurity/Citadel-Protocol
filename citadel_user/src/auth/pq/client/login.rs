use super::ksf::{password_input, password_keypair};
use super::register::ClientRegistration;
use crate::auth::pq::kem::{FactorKeypair, SharedSecret};
use crate::auth::pq::messages::{
    ChallengeBody, FactorChallenges, FactorTag, LoginChallenge, LoginFinish, LoginProof,
    LoginStart, RegFinish,
};
use crate::auth::pq::oprf::{self, OprfClientState};
use crate::auth::pq::proof::{factor_tag, session_key, TranscriptHash, AUTH_LABEL};
use crate::auth::pq::random_32;
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::{recovery_seed, security_key_seed, PrfOutput};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::FactorKind;
use citadel_types::crypto::SecBuffer;
use zeroize::Zeroizing;

/// What the embedding application must ask a security key for: a WebAuthn `get` with these
/// `allowCredentials` and the PRF extension evaluated at `prf_eval_salt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKeyRequest {
    pub credential_ids: Vec<Vec<u8>>,
    pub prf_eval_salt: [u8; 32],
}

/// The application's answer: which credential the user touched, and its PRF output.
#[derive(Debug)]
pub struct SecurityKeyAnswer {
    pub credential_id: Vec<u8>,
    pub prf: PrfOutput,
}

/// The client's answer to a [`LoginChallenge`].
pub enum ClientProof {
    Factors {
        proof: LoginProof,
        /// The same key the server derives; both add it to the session's pre-shared keys.
        session_key: Zeroizing<[u8; 32]>,
    },
    /// A legacy account: log in with the legacy credentials, and send `upgrade` alongside.
    Legacy { upgrade: Option<RegFinish> },
}

/// A login between [`LoginStart`] and the proof.
pub struct ClientLogin {
    password: Option<(Zeroizing<[u8; 32]>, OprfClientState)>,
    recovery: Option<FactorKeypair>,
}

impl ClientLogin {
    pub fn start(
        username: &str,
        password: Option<&SecBuffer>,
        recovery: Option<&RecoveryCode>,
    ) -> Result<(LoginStart, Self), AccountError> {
        let (password, oprf_blinded) = match password {
            Some(password) => {
                let input = password_input(password);
                let (state, blinded) = oprf::client_blind(input.as_ref())?;
                (Some((input, state)), Some(blinded))
            }
            None => (None, None),
        };
        let recovery = recovery
            .map(|code| FactorKeypair::derive(&recovery_seed(code)))
            .transpose()?;
        let start = LoginStart {
            username: username.to_string(),
            client_nonce: random_32(),
            oprf_blinded,
            recovery: recovery
                .as_ref()
                .map(|kp| kp.encapsulation_key().fingerprint()),
            // Set by the sign-in that sends this; a step-up inside a session needs neither.
            admission: None,
            resume: None,
        };
        Ok((start, Self { password, recovery }))
    }

    /// Whether answering `challenge` needs a security key, and what to ask it for.
    pub fn security_key_request(challenge: &LoginChallenge) -> Option<SecurityKeyRequest> {
        let ChallengeBody::Factors(factors) = &challenge.body else {
            return None;
        };
        let credential_ids: Vec<Vec<u8>> = factors
            .challenges
            .iter()
            .filter(|c| c.kind == FactorKind::SecurityKey)
            .filter_map(|c| c.credential_id.clone())
            .collect();
        (!credential_ids.is_empty()).then_some(SecurityKeyRequest {
            credential_ids,
            prf_eval_salt: factors.prf_eval_salt,
        })
    }

    /// Proves every challenged factor this client holds. Which of them suffice is the server's
    /// decision, by the account's policy; the client cannot tell a decoy from a real account.
    pub async fn respond(
        self,
        challenge: &LoginChallenge,
        transcript: &TranscriptHash,
        key: Option<SecurityKeyAnswer>,
    ) -> Result<ClientProof, AccountError> {
        let factors = match &challenge.body {
            ChallengeBody::Factors(factors) => factors,
            ChallengeBody::Legacy { upgrade } => {
                let upgrade = match (upgrade, self.password) {
                    (Some(reply), Some((input, oprf))) => {
                        let registration = ClientRegistration::resume(input, oprf);
                        Some(registration.finish(reply, false).await?.0)
                    }
                    _ => None,
                };
                return Ok(ClientProof::Legacy { upgrade });
            }
        };
        let password = self.password_keypair(factors).await?;
        let key = key
            .map(|answer| {
                let seed = security_key_seed(&answer.prf, &answer.credential_id);
                FactorKeypair::derive(&seed).map(|kp| (answer.credential_id, kp))
            })
            .transpose()?;

        let mut tags = Vec::new();
        let mut secrets: Vec<SharedSecret> = Vec::new();
        for c in &factors.challenges {
            let keypair = match c.kind {
                FactorKind::Password => password.as_ref(),
                FactorKind::SecurityKey => key
                    .as_ref()
                    .filter(|(id, _)| c.credential_id.as_ref() == Some(id))
                    .map(|(_, kp)| kp),
                FactorKind::RecoveryCode => self.recovery.as_ref(),
            };
            if let Some(keypair) = keypair {
                let k = keypair.decapsulate(&c.ct)?;
                tags.push(FactorTag {
                    factor_id: c.factor_id,
                    tag: factor_tag(&k, AUTH_LABEL, c.factor_id, transcript),
                });
                secrets.push(k);
            }
        }
        if tags.is_empty() {
            return Err(error!(
                ErrorCode::PqSignInFactorMissing,
                "none of the challenged factors"
            ));
        }
        let session_key = session_key(&secrets.iter().collect::<Vec<_>>(), transcript);
        Ok(ClientProof::Factors {
            proof: LoginProof::Factors(LoginFinish { tags }),
            session_key,
        })
    }

    async fn password_keypair(
        &self,
        factors: &FactorChallenges,
    ) -> Result<Option<FactorKeypair>, AccountError> {
        let challenged = factors
            .challenges
            .iter()
            .any(|c| c.kind == FactorKind::Password);
        match (&self.password, &factors.oprf_evaluated, challenged) {
            (Some((input, oprf)), Some(evaluated), true) => Ok(Some(
                password_keypair(input, oprf, evaluated, &factors.salt_user, factors.ksf).await?,
            )),
            _ => Ok(None),
        }
    }
}
