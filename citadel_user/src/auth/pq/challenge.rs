//! The public half of an admission check: what a client needs to SHOW the check a server asks
//! for, so that a server reached only through the protocol (no web page, no HTTP discovery) can
//! still be signed in to.
//!
//! Everything here is PUBLIC. A Turnstile site key is handed to every visitor of every page that
//! renders the widget, and the identity is the value the token is bound to (Turnstile's
//! `cData`). Never put a secret in a challenge: it is sent, unencrypted on a registration's
//! FAILURE, to anyone who asks to sign in.

use citadel_io::NetworkError;
use serde::{Deserialize, Serialize};

/// Who issues the tokens a challenge asks for. A client that does not know a provider ignores
/// the challenge (it decodes as absent) and shows a plain refusal.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdmissionProvider {
    /// Cloudflare Turnstile.
    Turnstile,
}

/// The check a refusal asks the client to complete before it tries again.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AdmissionChallenge {
    pub provider: AdmissionProvider,
    /// The provider's PUBLIC site key (Turnstile's `sitekey`).
    pub site_key: String,
    /// The value the token must be bound to (Turnstile's `cData`), when the server checks one.
    pub identity: Option<String>,
}

impl AdmissionChallenge {
    pub fn turnstile(site_key: impl Into<String>, identity: Option<String>) -> Self {
        Self {
            provider: AdmissionProvider::Turnstile,
            site_key: site_key.into(),
            identity,
        }
    }
}

/// The challenge a connect or register error carries, when the server's refusal sent one.
pub fn challenge_of(err: &NetworkError) -> Option<&AdmissionChallenge> {
    err.detail::<AdmissionChallenge>()
}
