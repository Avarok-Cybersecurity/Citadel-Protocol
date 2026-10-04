//! Admission: an optional, server-chosen check that a FRESH sign-in or registration must pass
//! before the server spends anything on it, such as a Cloudflare Turnstile token.
//!
//! It lives inside the login protocol, not in front of it. A WebSocket edge cannot tell a fresh
//! login from a reconnect, so gating the socket would either break every reconnect or be
//! bypassed by one. Here the server knows which is which: a login presenting a resume token its
//! held session recognises, and a recovery-code sign-in, are not asked.
//!
//! The token travels in `LoginStart`/`RegStart`, inside the post-quantum channel, and is never
//! printed: [`AdmissionToken`]'s `Debug` shows only that one is present.

use async_trait::async_trait;
use citadel_io::{error, ErrorCode, NetworkError};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

/// The token a client obtained for this sign-in or registration (a Turnstile response).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AdmissionToken(String);

impl AdmissionToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AdmissionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmissionToken(..)")
    }
}

/// What is being admitted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdmissionKind {
    SignIn,
    Register,
}

impl AdmissionKind {
    /// The name a token's issuer binds the token to (Turnstile's `action`), so a token obtained
    /// for one cannot be spent on the other.
    pub fn action(&self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::Register => "register",
        }
    }
}

/// What the policy decides on.
#[derive(Clone, Debug)]
pub struct AdmissionContext {
    pub username: String,
    pub kind: AdmissionKind,
    pub token: Option<AdmissionToken>,
    /// The client's address as this server sees it, when it has one.
    pub remote_addr: Option<IpAddr>,
}

/// Why a fresh sign-in or registration was not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// No token was sent and one is needed.
    Required,
    /// The token was refused (the reason, for the client to show).
    Failed(String),
}

/// The server's admission check. Called at most once per fresh sign-in or registration, before
/// any OPRF evaluation, encapsulation or Argon2 work.
#[async_trait]
pub trait AdmissionPolicy: Send + Sync {
    async fn admit(&self, ctx: AdmissionContext) -> Result<(), AdmissionRefusal>;
}

/// Runs `policy`, if the server set one (`ServerMiscSettings::admission`); with none, everyone
/// is admitted. `legacy_client` is a client below protocol 0.12, which cannot send a token: a
/// refusal tells it to update rather than to complete a check it has no way to show.
pub async fn check(
    policy: Option<&Arc<dyn AdmissionPolicy>>,
    ctx: AdmissionContext,
    legacy_client: bool,
) -> Result<(), NetworkError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let username = ctx.username.clone();
    let kind = ctx.kind;
    policy.admit(ctx).await.map_err(|refusal| {
        log::warn!(target: "citadel", "Admission refused a fresh {kind:?} for {username}: {refusal:?}");
        refusal_error(refusal, legacy_client)
    })
}

/// Runs the check for `ctx` (`None`: this login is not asked), and only then `work`: the OPRF
/// evaluation, the encapsulations, whatever the server would otherwise spend on a request it is
/// about to refuse. The order is the point, and this is where it is fixed.
pub async fn then<T>(
    policy: Option<&Arc<dyn AdmissionPolicy>>,
    ctx: Option<AdmissionContext>,
    legacy_client: bool,
    work: impl FnOnce() -> Result<T, NetworkError>,
) -> Result<T, NetworkError> {
    if let Some(ctx) = ctx {
        check(policy, ctx, legacy_client).await?;
    }
    work()
}

/// The error a refusal travels as. Its message is the code's own form, so a client can tell it
/// apart from any other failure ([`recognise`]).
pub fn refusal_error(refusal: AdmissionRefusal, legacy_client: bool) -> NetworkError {
    match (refusal, legacy_client) {
        (_, true) => error!(ErrorCode::PqSignInAdmissionNeedsUpdate),
        (AdmissionRefusal::Required, false) => error!(ErrorCode::PqSignInAdmissionRequired),
        (AdmissionRefusal::Failed(reason), false) => {
            error!(ErrorCode::PqSignInAdmissionFailed, reason)
        }
    }
}

/// The refusal a connect or register FAILURE's message is, if it is one, rebuilt as its error.
/// A FAILURE carries only a message, so the server sends the code's own form ([`refusal_error`])
/// and the client reads the code back here, for the application to tell a refused or missing
/// admission token apart from a wrong password.
pub fn refusal_from_message(message: &str) -> Option<NetworkError> {
    if message == ErrorCode::PqSignInAdmissionRequired.raw_string() {
        return Some(refusal_error(AdmissionRefusal::Required, false));
    }
    if message == ErrorCode::PqSignInAdmissionNeedsUpdate.raw_string() {
        return Some(refusal_error(AdmissionRefusal::Required, true));
    }
    let failed = ErrorCode::PqSignInAdmissionFailed.raw_string();
    let prefix = failed.strip_suffix("{}").unwrap_or(failed);
    let reason = message.strip_prefix(prefix)?;
    Some(refusal_error(
        AdmissionRefusal::Failed(reason.to_string()),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_reads_back_as_its_code_and_nothing_else_does() {
        for (refusal, legacy, code) in [
            (
                AdmissionRefusal::Required,
                false,
                ErrorCode::PqSignInAdmissionRequired,
            ),
            (
                AdmissionRefusal::Failed("expired".into()),
                false,
                ErrorCode::PqSignInAdmissionFailed,
            ),
            (
                AdmissionRefusal::Required,
                true,
                ErrorCode::PqSignInAdmissionNeedsUpdate,
            ),
        ] {
            let message = refusal_error(refusal, legacy).into_string();
            let read_back = refusal_from_message(&message).expect("not recognised");
            assert_eq!(read_back.code, code, "{message}");
            assert_eq!(read_back.into_string(), message, "the reason is lost");
        }
        assert!(refusal_from_message("Authentication failed").is_none());
        assert!(refusal_from_message("").is_none());
    }

    #[test]
    fn a_token_is_never_printed() {
        let token = AdmissionToken::new("0.secret-turnstile-response");
        assert!(!format!("{token:?}").contains("secret"));
    }

    #[test]
    fn the_actions_are_the_ones_the_ui_binds_tokens_to() {
        assert_eq!(AdmissionKind::SignIn.action(), "sign-in");
        assert_eq!(AdmissionKind::Register.action(), "register");
    }
}
