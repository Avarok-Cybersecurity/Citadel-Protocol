//! Resume credentials: signing in again without the account's factors.
//!
//! Ask a full sign-in for one with `SignInFactors::with_resume_lifetime`; the connection it
//! returns carries it (`CitadelClientServerConnection::resume`), with the moment it expires
//! (`ResumeCredential::valid_until_utc`). Sign in again with `SignInFactors::resume`. The server
//! refuses it as [`ErrorCode::ResumeCredentialExpired`] past that moment and as
//! [`ErrorCode::ResumeCredentialRevoked`] once the account's password, policy or keys have
//! changed; either way the user signs in again.

use crate::prelude::*;
use citadel_io::{error, ErrorCode};

/// The check made before anything is sent: a sign-in offering a resume credential that is past
/// its expiry at `now_utc` (Unix milliseconds) is refused here, by name.
pub(crate) fn refuse_expired(
    auth: &AuthenticationRequest,
    now_utc: u64,
) -> Result<(), NetworkError> {
    let AuthenticationRequest::SignIn { factors, .. } = auth else {
        return Ok(());
    };
    match &factors.resume {
        Some(credential) if credential.expired_at(now_utc) => {
            Err(error!(ErrorCode::ResumeCredentialExpired))
        }
        _ => Ok(()),
    }
}
