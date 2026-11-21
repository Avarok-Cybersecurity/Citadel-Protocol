//! Server: the admission check (`ServerMiscSettings::admission`) at the start of each FRESH
//! sign-in or registration, before the OPRF, any encapsulation or any Argon2 work.
//!
//! Not asked: a login whose resume token shows it to be an admitted session's own client
//! reconnecting: the session the server still holds recognises it, or the session it was issued
//! to ended within the policy's `resume_grace` (see `EndedSessions`). A recovery is asked like any
//! fresh sign-in, as `AdmissionKind::Recover`: it is the surface a guesser needs no bundle for. A
//! server without a policy admits everyone.

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use crate::proto::session_resume::ResumeToken;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::admission::{
    self, AdmissionContext, AdmissionKind, AdmissionPolicy, AdmissionToken,
};
use citadel_user::auth::pq::messages::LoginStart;
use std::sync::Arc;

/// The server's policy, if it set one.
pub(crate) fn policy<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
) -> Option<Arc<dyn AdmissionPolicy>> {
    session
        .account_manager
        .get_misc_settings()
        .admission
        .clone()
}

/// What a post-quantum client's `AUTH_START` is asked, or `None` when it is not.
pub(crate) async fn sign_in<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    start: &LoginStart,
) -> Option<AdmissionContext> {
    if let Some(token) = start.resume.map(ResumeToken::from_bytes) {
        if session
            .session_manager
            .resume_was_admitted(cid, &token)
            .await
        {
            return None;
        }
    }
    let token = start.admission.clone();
    let kind = match start.recovery {
        Some(_) => AdmissionKind::Recover,
        None => AdmissionKind::SignIn,
    };
    Some(context(session, &start.username, kind, token))
}

/// A login that sent no `AUTH_START`: a passwordless one, or one that offered no factors.
/// `presented` is the resume token its STAGE0 carried.
pub(crate) async fn legacy_sign_in<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    username: &str,
    presented: Option<&ResumeToken>,
) -> Result<(), NetworkError> {
    if let Some(token) = presented {
        if session
            .session_manager
            .resume_was_admitted(cid, token)
            .await
        {
            return Ok(());
        }
    }
    let ctx = context(session, username, AdmissionKind::SignIn, None);
    let policy = policy(session);
    admission::check(policy.as_ref(), ctx).await
}

/// What a registration is asked: `PQ_START`'s token, or none for a legacy STAGE2.
pub(crate) fn register<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    username: &str,
    token: Option<AdmissionToken>,
) -> AdmissionContext {
    context(session, username, AdmissionKind::Register, token)
}

fn context<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    username: &str,
    kind: AdmissionKind,
    token: Option<AdmissionToken>,
) -> AdmissionContext {
    AdmissionContext {
        username: username.to_string(),
        kind,
        token,
        remote_addr: Some(session.remote_peer.ip()),
    }
}
