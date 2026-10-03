//! How the SDK asks the embedding application for a security key's WebAuthn PRF output.
//!
//! The SDK never talks to an authenticator. When a sign-in, a step-up or an enrolment needs a key,
//! it sends a [`SecurityKeyChallenge`] down the channel [`security_key_channel`] returned. The
//! application (the agent relaying to the browser, or a browser client itself) runs
//! `navigator.credentials.get` with `allowCredentials` set to the request's credential ids and the
//! PRF extension evaluated at `prf_eval_salt`, and answers with the credential the user touched and
//! its 32-byte PRF output. The output never leaves the client.

use crate::error::NetworkError;
use citadel_io::tokio::sync::{mpsc, oneshot};
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::client::{SecurityKeyAnswer, SecurityKeyRequest};
use citadel_user::auth::pq::seed::PrfOutput;
use std::time::Duration;

/// The longest the SDK waits for the user to touch a key: the user-presence stage alone.
pub const KEY_PRESENCE_WINDOW: Duration = Duration::from_secs(60);

/// Why the SDK is asking.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecurityKeyPurpose {
    SignIn,
    /// A fresh proof of the account's factors before a change to them.
    StepUp,
    /// The key being added: its PRF output becomes the new factor.
    Enrol,
}

/// One request for a touch. Answer it once, or drop it to decline.
pub struct SecurityKeyChallenge {
    pub purpose: SecurityKeyPurpose,
    /// WebAuthn `allowCredentials`, and the PRF `eval.first` input.
    pub request: SecurityKeyRequest,
    responder: oneshot::Sender<Result<SecurityKeyAnswer, String>>,
}

impl SecurityKeyChallenge {
    /// The PRF output for credential `credential_id`, which must be one of the request's.
    pub fn answer(self, credential_id: Vec<u8>, prf_output: [u8; 32]) {
        let answer = SecurityKeyAnswer {
            credential_id,
            prf: PrfOutput::new(prf_output),
        };
        let _ = self.responder.send(Ok(answer));
    }

    /// The user cancelled, or the key has no PRF support.
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
        let allowed = request.credential_ids.clone();
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
            .map_err(|reason| error!(ErrorCode::PqSignInFactorMissing, reason))?;
        if !allowed.contains(&answer.credential_id) {
            return Err(missing(
                "a security key: the answer names a key that was not asked for",
            ));
        }
        Ok(answer)
    }
}
