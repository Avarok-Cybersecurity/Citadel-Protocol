//! What the client asks a security key for, and the relying party a challenge scopes it to.

use crate::auth::pq::messages::{AuthChallenge, ManagementChallenge};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// What the embedding application must ask a security key for: a WebAuthn ceremony for relying
/// party `rp_id`, with the PRF extension evaluated at `prf_eval_salt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKeyRequest {
    /// `None` only from a server at 0.12.2, which names no relying party: whoever serves the
    /// request uses its own, as it did for 0.12.2. Never `None` for a `Register` ceremony.
    pub rp_id: Option<String>,
    pub prf_eval_salt: [u8; 32],
    pub ceremony: SecurityKeyCeremony,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityKeyCeremony {
    /// A WebAuthn `get` with these `allowCredentials`.
    Authenticate { credential_ids: Vec<Vec<u8>> },
    /// A WebAuthn `create` of a non-discoverable credential with the PRF extension enabled, for
    /// the account `user_name`, on an authenticator holding none of `exclude_credential_ids`; then
    /// the new credential's PRF output.
    Register {
        user_id: Vec<u8>,
        user_name: String,
        exclude_credential_ids: Vec<Vec<u8>>,
    },
}

/// What a challenge says about the relying party its security keys are scoped to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RelyingParty<'a> {
    /// A server at 0.12.2 names none.
    Unnamed,
    /// The server named its relying party, or `None`: it has not enabled security keys.
    Named(Option<&'a str>),
}

impl<'a> RelyingParty<'a> {
    pub fn of_sign_in(challenge: &'a AuthChallenge) -> Self {
        match &challenge.ceremony {
            Some(ceremony) => Self::Named(ceremony.rp_id.as_deref()),
            None => Self::Unnamed,
        }
    }

    pub fn of_management(challenge: &'a ManagementChallenge) -> Self {
        match &challenge.ceremony {
            Some(ceremony) => Self::Named(ceremony.rp_id.as_deref()),
            None => Self::Unnamed,
        }
    }

    /// The `rp_id` of a request to authenticate with a key.
    pub(crate) fn for_authenticate(self) -> Result<Option<String>, AccountError> {
        match self {
            Self::Unnamed => Ok(None),
            Self::Named(rp_id) => named(rp_id).map(Some),
        }
    }

    /// The `rp_id` of a request to create a key, which only a named relying party can scope.
    pub(crate) fn for_register(self) -> Result<String, AccountError> {
        match self {
            Self::Unnamed => Err(error!(
                ErrorCode::PqSignInMalformed,
                "a security-key enrolment challenge without a relying party"
            )),
            Self::Named(rp_id) => named(rp_id),
        }
    }
}

fn named(rp_id: Option<&str>) -> Result<String, AccountError> {
    rp_id.map(str::to_owned).ok_or_else(|| {
        error!(
            ErrorCode::PqSignInUnavailable,
            "this server has not enabled security keys"
        )
    })
}
