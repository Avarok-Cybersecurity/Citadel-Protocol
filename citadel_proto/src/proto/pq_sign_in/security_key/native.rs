//! Security keys plugged into this machine, over USB, through Mozilla's `authenticator` crate: the
//! CTAP2 client Firefox uses. It runs WebAuthn's PRF extension itself, salt transform included, so
//! a key gives the same output here as in a browser for the same credential.

use super::reason::{ALREADY_ENROLLED, CANCELLED, NO_PRF};
use super::{
    security_key_channel, SecurityKeyChallenge, SecurityKeyPrf, SecurityKeyPurpose,
    KEY_PRESENCE_WINDOW,
};
use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::crypto::COSEAlgorithm;
use authenticator::ctap2::attestation::AuthenticatorDataFlags;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, AuthenticationExtensionsPRFInputs,
    AuthenticationExtensionsPRFValues, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
    ResidentKeyRequirement, Transport, UserVerificationRequirement,
};
use authenticator::errors::{AuthenticatorError, U2FTokenError};
use authenticator::statecallback::StateCallback;
use authenticator::{Pin, PinError, StatusPinUv, StatusUpdate};
use citadel_io::tokio::sync::oneshot;
use citadel_io::Mutex;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::pq::client::{SecurityKeyCeremony, SecurityKeyRequest};
use std::sync::{mpsc, Arc};

/// Nothing verifies the key's signature (the factor is its PRF output), so the client data it
/// signs carries nothing.
const UNSIGNED_CLIENT_DATA: [u8; 32] = [0u8; 32];

const NO_USER_VERIFICATION: &str =
    "This security key cannot verify its user with a PIN or biometrics, so it cannot sign in.";
/// Windows lets only an elevated process reach a security key over USB.
#[cfg(windows)]
const ELEVATION_REQUIRED: &str = "Access to the security key was denied. Run this application as \
                                  an administrator to use a security key.";

/// What a key asks of the user while it is used.
pub trait SecurityKeyPrompt: Send + Sync + 'static {
    /// The key's PIN, or `None` to cancel. `attempts_left` is set after an incorrect one. Called on
    /// a blocking thread: it may wait for the user.
    fn pin(&self, purpose: SecurityKeyPurpose, attempts_left: Option<u8>) -> Option<SecBuffer>;
    /// The key waits for a touch (with several plugged in, of the one to use).
    fn touch(&self, purpose: SecurityKeyPurpose);
}

/// The security keys plugged into this machine.
#[derive(Clone)]
pub struct SecurityKey {
    prompt: Arc<dyn SecurityKeyPrompt>,
}

/// A credential and its PRF output, or what to tell the user instead.
type Outcome = Result<(Vec<u8>, [u8; 32]), String>;

impl SecurityKey {
    pub fn new(prompt: impl SecurityKeyPrompt) -> Self {
        Self {
            prompt: Arc::new(prompt),
        }
    }

    /// A key channel this machine's keys answer, for `SignInFactors::with_security_key`. It is
    /// served, on the current Tokio runtime, until the SDK drops every handle to it.
    pub fn serve(&self) -> SecurityKeyPrf {
        let (prf, mut challenges) = security_key_channel();
        let key = self.clone();
        drop(citadel_io::tokio::spawn(async move {
            while let Some(challenge) = challenges.recv().await {
                key.answer(challenge).await;
            }
        }));
        prf
    }

    /// Runs `challenge`'s ceremony on this machine's keys, then answers it, or declines with what
    /// went wrong. If the SDK stops waiting, the key is cancelled.
    pub async fn answer(&self, mut challenge: SecurityKeyChallenge) {
        let ceremony = self.ceremony(challenge.purpose, &challenge.request);
        let outcome = citadel_io::tokio::select! {
            outcome = ceremony => outcome,
            () = challenge.responder.closed() => return,
        };
        match outcome {
            Ok((credential_id, prf)) => challenge.answer(credential_id, prf),
            Err(reason) => challenge.decline(reason),
        }
    }

    async fn ceremony(&self, purpose: SecurityKeyPurpose, request: &SecurityKeyRequest) -> Outcome {
        // TODO: the Windows WebAuthn API (webauthn.dll), which reaches keys without elevation.
        #[cfg(windows)]
        if !check_elevation::is_elevated().unwrap_or(false) {
            return Err(ELEVATION_REQUIRED.into());
        }
        let mut session = Session::new(self.prompt.clone(), purpose)?;
        match &request.ceremony {
            SecurityKeyCeremony::Authenticate { credential_ids } => {
                session.authenticate(request, credential_ids).await
            }
            SecurityKeyCeremony::Register {
                user_id,
                user_name,
                exclude_credential_ids,
            } => {
                let credential_id = session
                    .register(request, user_id, user_name, exclude_credential_ids)
                    .await?;
                session.authenticate(request, &[credential_id]).await
            }
        }
    }
}

/// One ceremony's use of the keys. Dropping it cancels whatever a key is doing.
struct Session {
    service: AuthenticatorService,
    prompt: Arc<dyn SecurityKeyPrompt>,
    purpose: SecurityKeyPurpose,
    /// The PIN the user last gave, so the `get` after a registration does not ask again.
    pin: Arc<Mutex<Option<SecBuffer>>>,
}

impl Session {
    fn new(
        prompt: Arc<dyn SecurityKeyPrompt>,
        purpose: SecurityKeyPurpose,
    ) -> Result<Self, String> {
        let mut service = AuthenticatorService::new()
            .map_err(|err| format!("Security keys are unavailable on this system: {err}"))?;
        service.add_u2f_usb_hid_platform_transports();
        Ok(Self {
            service,
            prompt,
            purpose,
            pin: Arc::default(),
        })
    }

    /// Creates a non-discoverable credential with the PRF extension enabled, and returns its id.
    async fn register(
        &mut self,
        request: &SecurityKeyRequest,
        user_id: &[u8],
        user_name: &str,
        exclude_credential_ids: &[Vec<u8>],
    ) -> Result<Vec<u8>, String> {
        let args = RegisterArgs {
            client_data_hash: UNSIGNED_CLIENT_DATA,
            relying_party: RelyingParty {
                id: request.rp_id.clone(),
                name: None,
            },
            origin: origin(&request.rp_id),
            user: PublicKeyCredentialUserEntity {
                id: user_id.to_vec(),
                name: Some(user_name.to_string()),
                display_name: None,
            },
            pub_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }],
            exclude_list: descriptors(exclude_credential_ids),
            user_verification_req: UserVerificationRequirement::Required,
            resident_key_req: ResidentKeyRequirement::Discouraged,
            extensions: AuthenticationExtensionsClientInputs {
                prf: Some(AuthenticationExtensionsPRFInputs::default()),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        let (callback, result) = callback();
        let status = self.status();
        self.service
            .register(timeout_ms(), args, status, callback)
            .map_err(describe)?;
        let made = result
            .await
            .map_err(|_| CANCELLED.to_string())?
            .map_err(describe)?;
        if made.extensions.prf.and_then(|prf| prf.enabled) == Some(false) {
            return Err(NO_PRF.into());
        }
        let auth_data = made.att_obj.auth_data;
        if !auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED)
        {
            return Err(NO_USER_VERIFICATION.into());
        }
        auth_data
            .credential_data
            .map(|credential| credential.credential_id)
            .ok_or_else(|| "The security key created no credential.".to_string())
    }

    /// A `get` of one of `credential_ids`, with the PRF evaluated at the request's salt.
    async fn authenticate(
        &mut self,
        request: &SecurityKeyRequest,
        credential_ids: &[Vec<u8>],
    ) -> Outcome {
        let prf = AuthenticationExtensionsPRFInputs {
            eval: Some(AuthenticationExtensionsPRFValues {
                first: request.prf_eval_salt.to_vec(),
                second: None,
            }),
            eval_by_credential: None,
        };
        let args = SignArgs {
            client_data_hash: UNSIGNED_CLIENT_DATA,
            origin: origin(&request.rp_id),
            relying_party_id: request.rp_id.clone(),
            allow_list: descriptors(credential_ids),
            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                prf: Some(prf),
                ..Default::default()
            },
            pin: self.remembered_pin(),
            use_ctap1_fallback: false,
        };
        let (callback, result) = callback();
        let status = self.status();
        self.service
            .sign(timeout_ms(), args, status, callback)
            .map_err(describe)?;
        let signed = result
            .await
            .map_err(|_| CANCELLED.to_string())?
            .map_err(describe)?;
        let assertion = signed.assertion;
        if !assertion
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED)
        {
            return Err(NO_USER_VERIFICATION.into());
        }
        // CTAP 2.1 always names the credential; a 2.0 key may omit it when only one was allowed.
        let credential_id = match (assertion.credentials, credential_ids) {
            (Some(credential), _) => credential.id,
            (None, [only]) => only.clone(),
            (None, _) => {
                return Err("The security key did not say which credential it used.".into())
            }
        };
        let output = signed
            .extensions
            .prf
            .and_then(|prf| prf.results)
            .ok_or(NO_PRF)?
            .first;
        let output = output
            .try_into()
            .map_err(|_| "The security key returned a malformed PRF output.".to_string())?;
        Ok((credential_id, output))
    }

    fn remembered_pin(&self) -> Option<Pin> {
        let pin = self.pin.lock();
        let text = std::str::from_utf8(pin.as_ref()?.as_ref()).ok()?;
        Some(Pin::new(text))
    }

    /// Where the key's status goes: touches and PIN requests reach the prompt, on a thread of their
    /// own, since the prompt may block. Failures arrive as the ceremony's result instead.
    fn status(&self) -> mpsc::Sender<StatusUpdate> {
        let (status, updates) = mpsc::channel();
        let prompt = self.prompt.clone();
        let purpose = self.purpose;
        let remembered = self.pin.clone();
        drop(std::thread::spawn(move || {
            for update in updates {
                match update {
                    StatusUpdate::PresenceRequired | StatusUpdate::SelectDeviceNotice => {
                        prompt.touch(purpose)
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(reply)) => {
                        ask_pin(&*prompt, purpose, None, &remembered, reply)
                    }
                    StatusUpdate::PinUvError(StatusPinUv::InvalidPin(reply, attempts_left)) => {
                        ask_pin(&*prompt, purpose, attempts_left, &remembered, reply)
                    }
                    _ => {}
                }
            }
        }));
        status
    }
}

/// Asks the prompt for the PIN and hands it to the key. Leaving `reply` unanswered cancels.
fn ask_pin(
    prompt: &dyn SecurityKeyPrompt,
    purpose: SecurityKeyPurpose,
    attempts_left: Option<u8>,
    remembered: &Mutex<Option<SecBuffer>>,
    reply: mpsc::Sender<Pin>,
) {
    let Some(pin) = prompt.pin(purpose, attempts_left) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(pin.as_ref()) else {
        return;
    };
    if reply.send(Pin::new(text)).is_ok() {
        *remembered.lock() = Some(pin);
    }
}

fn callback<T: Send + 'static>() -> (
    StateCallback<authenticator::Result<T>>,
    oneshot::Receiver<authenticator::Result<T>>,
) {
    let (tx, rx) = oneshot::channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = tx.send(result);
    }));
    (callback, rx)
}

fn descriptors(credential_ids: &[Vec<u8>]) -> Vec<PublicKeyCredentialDescriptor> {
    credential_ids
        .iter()
        .map(|id| PublicKeyCredentialDescriptor {
            id: id.clone(),
            transports: vec![Transport::USB],
        })
        .collect()
}

fn origin(rp_id: &str) -> String {
    format!("https://{rp_id}")
}

fn timeout_ms() -> u64 {
    KEY_PRESENCE_WINDOW.as_millis() as u64
}

/// What the user is told when a key fails.
fn describe(err: AuthenticatorError) -> String {
    let reason = match err {
        AuthenticatorError::CredentialExcluded => ALREADY_ENROLLED,
        AuthenticatorError::PinError(PinError::PinNotSet) => {
            "This security key has no PIN. Set a PIN on it, then try again."
        }
        AuthenticatorError::PinError(PinError::InvalidPin(_)) => "Incorrect PIN.",
        AuthenticatorError::PinError(PinError::PinAuthBlocked) => {
            "Too many incorrect PINs. Remove and reinsert the security key, then try again."
        }
        AuthenticatorError::PinError(PinError::PinBlocked) => {
            "This security key is locked after too many incorrect PINs and must be reset."
        }
        AuthenticatorError::PinError(PinError::InvalidUv(_) | PinError::UvBlocked) => {
            "The security key could not verify you."
        }
        AuthenticatorError::CancelledByUser => CANCELLED,
        AuthenticatorError::U2FToken(U2FTokenError::NotAllowed) => {
            "No security key was used in time."
        }
        other => return format!("The security key failed: {other}"),
    };
    reason.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::time::Duration;

    /// A user who cancels any PIN prompt.
    struct Cancels;

    impl SecurityKeyPrompt for Cancels {
        fn pin(&self, _: SecurityKeyPurpose, _: Option<u8>) -> Option<SecBuffer> {
            None
        }

        fn touch(&self, _: SecurityKeyPurpose) {}
    }

    #[citadel_io::tokio::test]
    async fn a_challenge_the_sdk_stops_waiting_for_is_cancelled() {
        let (prf, mut challenges) = security_key_channel();
        let request = SecurityKeyRequest {
            rp_id: "localhost".into(),
            prf_eval_salt: [0u8; 32],
            ceremony: SecurityKeyCeremony::Authenticate {
                credential_ids: vec![b"credential".to_vec()],
            },
        };
        let waiting =
            tokio::spawn(async move { prf.ask(SecurityKeyPurpose::SignIn, request).await });
        let challenge = challenges.recv().await.unwrap();
        waiting.abort();
        let key = SecurityKey::new(Cancels);
        tokio::time::timeout(Duration::from_secs(10), key.answer(challenge))
            .await
            .expect("the key was left running after the SDK stopped waiting");
    }
}
