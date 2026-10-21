//! Security keys through the browser's WebAuthn API. The browser finds the key, asks for its PIN
//! and touch, and runs the PRF extension itself, so a key gives the same output here as it does
//! natively for the same credential.
//!
//! The PRF options are built as plain objects: `web-sys` gates its PRF bindings behind
//! `web_sys_unstable_apis`, which every downstream build would then have to set.

use super::reason::{ALREADY_ENROLLED, CANCELLED, NO_PRF};
use super::{security_key_channel, SecurityKeyChallenge, SecurityKeyPrf, KEY_PRESENCE_WINDOW};
use crate::proto::misc::wasm_promise::settle;
use citadel_user::auth::pq::client::{SecurityKeyCeremony, SecurityKeyRequest};
use futures::future::{select, Either};
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::pin::pin;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    AbortController, AbortSignal, CredentialCreationOptions, CredentialRequestOptions,
    CredentialsContainer, PublicKeyCredential,
};

/// Nothing verifies the key's signature (the factor is its PRF output), so the challenge it signs
/// carries nothing.
const UNSIGNED_CHALLENGE: [u8; 32] = [0u8; 32];

/// A credential and its PRF output, or what to tell the user instead.
type Outcome = Result<(Vec<u8>, [u8; 32]), String>;

/// The security keys this browser can reach. The browser asks the user for the PIN and the touch
/// itself, and requires them: every ceremony asks for user verification. The page must be served
/// from the server's relying party ID or a subdomain of it, and run in a window, not a worker.
/// Tested in Chrome and Firefox.
#[derive(Clone, Default)]
pub struct SecurityKey;

impl SecurityKey {
    pub fn new() -> Self {
        Self
    }

    /// A key channel the browser's keys answer, for `SignInFactors::with_security_key`. It is
    /// served on the page's event loop, from wherever this is called, until the SDK drops every
    /// handle to it.
    pub fn serve(&self) -> SecurityKeyPrf {
        let (prf, mut challenges) = security_key_channel();
        let key = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(challenge) = challenges.recv().await {
                key.answer(challenge).await;
            }
        });
        prf
    }

    /// Runs `challenge`'s ceremony in the browser, then answers it, or declines with what went
    /// wrong. If the SDK stops waiting, the browser's request is aborted.
    pub async fn answer(&self, mut challenge: SecurityKeyChallenge) {
        let controller = match AbortController::new() {
            Ok(controller) => controller,
            Err(err) => return challenge.decline(failure(&err)),
        };
        let signal = controller.signal();
        let outcome = {
            let ceremony = pin!(ceremony(&challenge.request, &signal));
            let abandoned = pin!(challenge.responder.closed());
            match select(ceremony, abandoned).await {
                Either::Left((outcome, _)) => Some(outcome),
                Either::Right(_) => None,
            }
        };
        match outcome {
            Some(Ok((credential_id, prf))) => challenge.answer(credential_id, prf),
            Some(Err(reason)) => challenge.decline(reason),
            None => controller.abort(),
        }
    }
}

async fn ceremony(request: &SecurityKeyRequest, signal: &AbortSignal) -> Outcome {
    let window = web_sys::window().ok_or_else(|| {
        "Security keys need a browser window; a worker cannot reach them.".to_string()
    })?;
    let credentials = window.navigator().credentials();
    match &request.ceremony {
        SecurityKeyCeremony::Authenticate { credential_ids } => {
            authenticate(&credentials, request, credential_ids, signal).await
        }
        SecurityKeyCeremony::Register {
            user_id,
            user_name,
            exclude_credential_ids,
        } => {
            let created = create(
                &credentials,
                request,
                user_id,
                user_name,
                exclude_credential_ids,
                signal,
            )
            .await?;
            authenticate(&credentials, request, &[created], signal).await
        }
    }
}

/// `navigator.credentials.create` of a non-discoverable credential with the PRF extension
/// enabled; returns its id.
async fn create(
    credentials: &CredentialsContainer,
    request: &SecurityKeyRequest,
    user_id: &[u8],
    user_name: &str,
    exclude_credential_ids: &[Vec<u8>],
    signal: &AbortSignal,
) -> Result<Vec<u8>, String> {
    let rp_id = JsValue::from_str(&request.rp_id);
    let public_key = object(&[
        ("rp", object(&[("id", rp_id.clone()), ("name", rp_id)])),
        (
            "user",
            object(&[
                ("id", bytes(user_id)),
                ("name", user_name.into()),
                ("displayName", user_name.into()),
            ]),
        ),
        ("challenge", bytes(&UNSIGNED_CHALLENGE)),
        (
            "pubKeyCredParams",
            Array::of1(&object(&[
                ("type", "public-key".into()),
                ("alg", (-7).into()),
            ]))
            .into(),
        ),
        (
            "authenticatorSelection",
            object(&[
                ("residentKey", "discouraged".into()),
                ("userVerification", "required".into()),
            ]),
        ),
        ("excludeCredentials", descriptors(exclude_credential_ids)),
        ("timeout", timeout_ms()),
        ("extensions", object(&[("prf", Object::new().into())])),
    ]);
    let options = CredentialCreationOptions::new();
    set(&options, "publicKey", public_key);
    options.set_signal(signal);
    let promise = credentials
        .create_with_options(&options)
        .map_err(|err| failure(&err))?;
    let credential: PublicKeyCredential = settle(promise)
        .await
        .map_err(|err| describe(&err, &request.rp_id))?
        .unchecked_into();
    let enabled = path(&extension_results(&credential), &["prf", "enabled"]);
    if enabled == Some(JsValue::FALSE) {
        return Err(NO_PRF.into());
    }
    Ok(Uint8Array::new(&credential.raw_id()).to_vec())
}

/// `navigator.credentials.get` of one of `credential_ids`, with the PRF evaluated at the request's
/// salt.
async fn authenticate(
    credentials: &CredentialsContainer,
    request: &SecurityKeyRequest,
    credential_ids: &[Vec<u8>],
    signal: &AbortSignal,
) -> Outcome {
    let eval = object(&[("first", bytes(&request.prf_eval_salt))]);
    let public_key = object(&[
        ("challenge", bytes(&UNSIGNED_CHALLENGE)),
        ("rpId", JsValue::from_str(&request.rp_id)),
        ("allowCredentials", descriptors(credential_ids)),
        ("userVerification", "required".into()),
        ("timeout", timeout_ms()),
        ("extensions", object(&[("prf", object(&[("eval", eval)]))])),
    ]);
    let options = CredentialRequestOptions::new();
    set(&options, "publicKey", public_key);
    options.set_signal(signal);
    let promise = credentials
        .get_with_options(&options)
        .map_err(|err| failure(&err))?;
    let credential: PublicKeyCredential = settle(promise)
        .await
        .map_err(|err| describe(&err, &request.rp_id))?
        .unchecked_into();
    let output = path(
        &extension_results(&credential),
        &["prf", "results", "first"],
    )
    .ok_or(NO_PRF)?;
    let output = Uint8Array::new(&output)
        .to_vec()
        .try_into()
        .map_err(|_| "The security key returned a malformed PRF output.".to_string())?;
    Ok((Uint8Array::new(&credential.raw_id()).to_vec(), output))
}

fn extension_results(credential: &PublicKeyCredential) -> JsValue {
    credential.get_client_extension_results().into()
}

/// `value[keys[0]][keys[1]]…`, or `None` where a step is missing.
fn path(value: &JsValue, keys: &[&str]) -> Option<JsValue> {
    keys.iter().try_fold(value.clone(), |value, key| {
        Reflect::get(&value, &JsValue::from_str(key))
            .ok()
            .filter(|next| !next.is_undefined() && !next.is_null())
    })
}

fn object(fields: &[(&str, JsValue)]) -> JsValue {
    let object = Object::new();
    for (key, value) in fields {
        set(&object, key, value.clone());
    }
    object.into()
}

fn set(target: &JsValue, key: &str, value: JsValue) {
    // Setting a property on an object this module created cannot fail.
    let _ = Reflect::set(target, &JsValue::from_str(key), &value);
}

fn bytes(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).into()
}

fn descriptors(credential_ids: &[Vec<u8>]) -> JsValue {
    credential_ids
        .iter()
        .map(|id| object(&[("type", "public-key".into()), ("id", bytes(id))]))
        .collect::<Array>()
        .into()
}

fn timeout_ms() -> JsValue {
    (KEY_PRESENCE_WINDOW.as_millis() as f64).into()
}

/// What the user is told when the browser refuses, by the `DOMException`'s name.
fn describe(rejection: &JsValue, rp_id: &str) -> String {
    let name = path(rejection, &["name"]).and_then(|name| name.as_string());
    match name.as_deref() {
        // Browsers do not say which: a cancelled prompt and a timeout look the same, on purpose.
        Some("NotAllowedError") => "The security key request was cancelled or timed out.".into(),
        Some("InvalidStateError") => ALREADY_ENROLLED.into(),
        Some("AbortError") => CANCELLED.into(),
        Some("SecurityError") => format!(
            "This page cannot use security keys for {rp_id}: it must be served from {rp_id} or \
             one of its subdomains."
        ),
        Some("NotSupportedError") => "This browser cannot use security keys this way.".into(),
        _ => failure(rejection),
    }
}

fn failure(err: &JsValue) -> String {
    let message = path(err, &["message"])
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| format!("{err:?}"));
    format!("The security key failed: {message}")
}
