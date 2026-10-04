//! Server: the admission check (`ServerMiscSettings::admission`) at the start of each FRESH
//! sign-in or registration, before the OPRF, any encapsulation or any Argon2 work.
//!
//! Not asked: a recovery-code sign-in (the user's way back in) and a login whose resume token
//! the session the server still holds recognises (its own client reconnecting, admitted once
//! already). A server without a policy admits everyone.

use super::runs_with;
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
pub(crate) fn sign_in<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    start: &LoginStart,
) -> Option<AdmissionContext> {
    if start.recovery.is_some() {
        return None;
    }
    let resumed = start.resume.map(ResumeToken::from_bytes);
    if resumed.is_some_and(|token| session.session_manager.held_session_recognises(cid, &token)) {
        return None;
    }
    let token = start.admission.clone();
    Some(context(
        session,
        &start.username,
        AdmissionKind::SignIn,
        token,
    ))
}

/// A login that sent no `AUTH_START`: a client below 0.12, which cannot carry a token, or a
/// transient one. `presented` is the resume token its STAGE0 carried.
pub(crate) async fn legacy_sign_in<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    username: &str,
    presented: Option<&ResumeToken>,
    adjacent_version: u32,
) -> Result<(), NetworkError> {
    if presented.is_some_and(|token| session.session_manager.held_session_recognises(cid, token)) {
        return Ok(());
    }
    let ctx = context(session, username, AdmissionKind::SignIn, None);
    let policy = policy(session);
    admission::check(policy.as_ref(), ctx, is_legacy_client(adjacent_version)).await
}

/// What a registration is asked: `PQ_START`'s token, or none for a legacy STAGE2.
pub(crate) fn register<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    username: &str,
    token: Option<AdmissionToken>,
) -> AdmissionContext {
    context(session, username, AdmissionKind::Register, token)
}

/// A client below protocol 0.12 has no way to send a token, so a refusal tells it to update.
pub(crate) fn is_legacy_client(adjacent_version: u32) -> bool {
    !runs_with(adjacent_version)
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
