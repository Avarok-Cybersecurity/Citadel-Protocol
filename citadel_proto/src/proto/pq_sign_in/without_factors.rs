//! A login or registration that ran no post-quantum exchange (no `AUTH_START`, no `PQ_START`).
//!
//! Since the Argon2 sunset that is only ever a passwordless (transient) one. A password login or
//! registration without the exchange is refused before any other work: a client below protocol
//! 0.12 is told to update ([`ErrorCode::PqSignInAdmissionNeedsUpdate`]), since it can do nothing
//! else, and a newer one, which should have run the exchange, gets
//! [`ErrorCode::PqSignInLegacyRefused`].

use super::admission::is_legacy_client;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::admission;
use citadel_user::auth::proposed_credentials::ProposedCredentials;

pub(crate) fn refuse_unless_passwordless(
    adjacent_version: u32,
    credentials: &ProposedCredentials,
) -> Result<(), NetworkError> {
    if credentials.is_passwordless() {
        return Ok(());
    }
    if is_legacy_client(adjacent_version) {
        return Err(error!(ErrorCode::PqSignInAdmissionNeedsUpdate));
    }
    Err(error!(ErrorCode::PqSignInLegacyRefused))
}

/// Server: a STAGE2 that carries no keys. Passwordless or refused; one that no `PQ_START`
/// admitted is asked for admission now, before the account is created.
pub(crate) async fn admit_stage2<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    adjacent_version: u32,
    credentials: &ProposedCredentials,
    admitted: bool,
) -> Result<(), NetworkError> {
    refuse_unless_passwordless(adjacent_version, credentials)?;
    if admitted {
        return Ok(());
    }
    let ctx = super::admission::register(session, credentials.username(), None);
    let policy = super::admission::policy(session);
    admission::check(policy.as_ref(), ctx, is_legacy_client(adjacent_version)).await
}
