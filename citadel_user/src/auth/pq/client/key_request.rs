//! What the client asks a security key for, and the relying party a challenge scopes it to.

use crate::auth::pq::messages::{AuthChallenge, ManagementChallenge};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// What the embedding application must ask a security key for: a WebAuthn ceremony for relying
/// party `rp_id`, with the PRF extension evaluated at `prf_eval_salt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKeyRequest {
    pub rp_id: String,
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

/// The relying party a challenge scopes its security keys to: `None` when the server has not
/// enabled security keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty<'a>(pub Option<&'a str>);

impl<'a> RelyingParty<'a> {
    pub fn of_sign_in(challenge: &'a AuthChallenge) -> Self {
        Self(challenge.ceremony.rp_id.as_deref())
    }

    pub fn of_management(challenge: &'a ManagementChallenge) -> Self {
        Self(challenge.ceremony.rp_id.as_deref())
    }

    /// The `rp_id` of a request to authenticate with, or to create, a key.
    pub(crate) fn rp_id(self) -> Result<String, AccountError> {
        self.0.map(str::to_owned).ok_or_else(|| {
            error!(
                ErrorCode::PqSignInUnavailable,
                "this server has not enabled security keys"
            )
        })
    }
}
