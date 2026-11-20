//! The server's sign-in throttle as a session applies it: every guess at an account's factors
//! (a sign-in, a full session's step-up, a recovery) is admitted here before the server does any
//! work for it, and its outcome is recorded here once its proof is checked. The source is the
//! session's remote address; the clock is the wall clock.

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::includes::*;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::throttle::{Attempt, Decision};
use citadel_user::misc::now_ms;

/// Refuses, as `PqSignInFailed` (what a wrong factor reads), an attempt over the throttle. A
/// server without post-quantum settings challenges nothing, so it has nothing to throttle.
pub(crate) fn admit<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    username: &str,
    attempt: Attempt,
) -> Result<(), NetworkError> {
    let Some(settings) = session.account_manager.pq_settings() else {
        return Ok(());
    };
    let source = Some(session.remote_peer.ip());
    match settings.throttle_admit(username, source, attempt, now_ms()) {
        Decision::Admit => Ok(()),
        Decision::Refuse => {
            log::warn!(target: "citadel", "Throttled a {attempt:?} attempt for {username}");
            Err(error!(ErrorCode::PqSignInFailed))
        }
    }
}

/// Records whether an admitted attempt's proof verified.
pub(crate) fn outcome<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    username: &str,
    attempt: Attempt,
    verified: bool,
) {
    if let Some(settings) = session.account_manager.pq_settings() {
        let source = Some(session.remote_peer.ip());
        settings.throttle_outcome(username, source, attempt, verified, now_ms());
    }
}
