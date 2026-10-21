//! How the SDK asks the embedding application for a security key's WebAuthn PRF output.
//!
//! The protocol never talks to an authenticator. When a sign-in, a step-up or an enrolment needs a
//! key, it sends a [`SecurityKeyChallenge`] down the channel [`security_key_channel`] returned.
//! Whoever serves the channel (the `security-key` feature's `SecurityKey` for keys plugged into
//! this machine, or the application itself, such as an agent relaying to a browser) runs the
//! request's WebAuthn ceremony for its relying party ID (which the server names), with the PRF
//! extension evaluated at `prf_eval_salt`:
//!
//! - [`SecurityKeyCeremony::Authenticate`]: `navigator.credentials.get` with `allowCredentials`
//!   set to the request's credential ids.
//! - [`SecurityKeyCeremony::Register`]: `navigator.credentials.create` with the PRF extension
//!   enabled and `excludeCredentials` set to the request's, then a `get` of the new credential.
//!
//! It answers with the credential and its 32-byte PRF output. The output never leaves the client.

use crate::error::NetworkError;
use citadel_io::tokio::sync::{mpsc, oneshot};
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::client::{SecurityKeyAnswer, SecurityKeyCeremony, SecurityKeyRequest};
use citadel_user::auth::pq::seed::PrfOutput;
use std::time::Duration;

#[cfg(all(feature = "security-key", not(target_family = "wasm")))]
mod native;
#[cfg(all(feature = "security-key", not(target_family = "wasm")))]
pub use native::{SecurityKey, SecurityKeyPrompt};

/// The longest the SDK waits for the user to touch a key: the user-presence stage alone.
pub const KEY_PRESENCE_WINDOW: Duration = Duration::from_secs(60);

/// Why the SDK is asking.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecurityKeyPurpose {
    SignIn,
    /// A fresh proof of the account's factors before a change to them.
    StepUp,
    /// The key being added: its new credential's PRF output becomes the new factor.
    Enrol,
}

/// One request for a touch. Answer it once, or drop it to decline.
pub struct SecurityKeyChallenge {
    pub purpose: SecurityKeyPurpose,
    /// The WebAuthn ceremony to run, and the PRF `eval.first` input.
    pub request: SecurityKeyRequest,
    responder: oneshot::Sender<Result<SecurityKeyAnswer, String>>,
}

impl SecurityKeyChallenge {
    /// The PRF output for credential `credential_id`: one of the request's when authenticating,
    /// the new credential when registering.
    pub fn answer(self, credential_id: Vec<u8>, prf_output: [u8; 32]) {
        let answer = SecurityKeyAnswer {
            credential_id,
            prf: PrfOutput::new(prf_output),
        };
        let _ = self.responder.send(Ok(answer));
    }

    /// Declines, saying why in words for the user: the caller's error is `reason` itself.
    pub fn decline(self, reason: impl Into<String>) {
        let _ = self.responder.send(Err(reason.into()));
    }
}

impl std::fmt::Debug for SecurityKeyChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityKeyChallenge")
            .field("purpose", &self.purpose)
            .field("request", &self.request)
            .finish()
    }
}

/// The SDK's end of the channel; pass it in [`crate::auth::SignInFactors`].
#[derive(Clone, Debug)]
pub struct SecurityKeyPrf {
    tx: mpsc::UnboundedSender<SecurityKeyChallenge>,
}

/// A channel for security-key requests: hand the first half to the SDK, serve the second.
pub fn security_key_channel() -> (
    SecurityKeyPrf,
    mpsc::UnboundedReceiver<SecurityKeyChallenge>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    (SecurityKeyPrf { tx }, rx)
}

impl SecurityKeyPrf {
    /// Asks the application, waiting at most [`KEY_PRESENCE_WINDOW`].
    pub async fn ask(
        &self,
        purpose: SecurityKeyPurpose,
        request: SecurityKeyRequest,
    ) -> Result<SecurityKeyAnswer, NetworkError> {
        let (responder, answer) = oneshot::channel();
        let ceremony = request.ceremony.clone();
        let challenge = SecurityKeyChallenge {
            purpose,
            request,
            responder,
        };
        let missing = |why: &'static str| error!(ErrorCode::PqSignInFactorMissing, why);
        self.tx
            .send(challenge)
            .map_err(|_| missing("a security key: nobody is serving the key channel"))?;
        let answer = citadel_io::time::timeout(KEY_PRESENCE_WINDOW, answer)
            .await
            .map_err(|_| missing("a security key: no touch within 60 seconds"))?
            .map_err(|_| missing("a security key: the request was dropped"))?
            .map_err(|reason| error!(ErrorCode::PqSignInSecurityKey, reason))?;
        let asked_for = match &ceremony {
            SecurityKeyCeremony::Authenticate { credential_ids } => {
                credential_ids.contains(&answer.credential_id)
            }
            SecurityKeyCeremony::Register {
                exclude_credential_ids,
                ..
            } => {
                !answer.credential_id.is_empty()
                    && !exclude_credential_ids.contains(&answer.credential_id)
            }
        };
        if !asked_for {
            return Err(missing(
                "a security key: the answer names a key that was not asked for",
            ));
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;

    #[citadel_io::tokio::test]
    async fn a_declined_request_fails_with_the_keys_own_words() {
        let (prf, mut challenges) = security_key_channel();
        let reason = "This security key is already enrolled on this account.";
        drop(tokio::spawn(async move {
            challenges.recv().await.unwrap().decline(reason);
        }));
        let request = SecurityKeyRequest {
            rp_id: "localhost".into(),
            prf_eval_salt: [0u8; 32],
            ceremony: SecurityKeyCeremony::Authenticate {
                credential_ids: vec![b"credential".to_vec()],
            },
        };
        let declined = prf
            .ask(SecurityKeyPurpose::Enrol, request)
            .await
            .unwrap_err();
        assert_eq!(declined.code, ErrorCode::PqSignInSecurityKey);
        assert_eq!(declined.into_string(), reason);
    }
}
