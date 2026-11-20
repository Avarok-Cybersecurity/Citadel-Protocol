//! Server: the sign-in management requests of an authenticated session, carried in
//! `PeerSignal::SignInManagement`. Every change is applied to the record as stored, under the
//! account manager's record lock.

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::messages::{ManagementDone, ManagementMessage, SignInLayout};
use citadel_user::auth::pq::server::{
    begin_management, Change, CommitStep, PendingEnrol, PendingManagement,
};
use citadel_user::auth::pq::throttle::Attempt;
use citadel_user::misc::now_ms;

/// Where a session's management exchange is.
pub(crate) enum ServerManagement {
    Pending(Box<PendingManagement>),
    Enrolling(PendingEnrol),
}

/// Client: whether the server at `server_version` can read `message`. A server below
/// `PQ_SIGN_IN_SINCE` reads no management message; one below `SECURITY_KEY_CEREMONY_SINCE` cannot
/// enrol a key whose credential the client creates after the challenge.
pub(crate) fn sendable(
    message: &ManagementMessage,
    server_version: Option<u32>,
) -> Result<(), NetworkError> {
    if !super::runs_with_known(server_version) {
        return Err(error!(
            ErrorCode::PqSignInUnavailable,
            "the server predates post-quantum sign-in"
        ));
    }
    if let ManagementMessage::Begin(begin) = message {
        if begin.op.needs_recovery_release() && !super::recover::server_recovers(server_version) {
            return Err(error!(ErrorCode::RecoveryUnsupported));
        }
    }
    let needed = match message {
        ManagementMessage::Begin(begin) => begin.op.layout(),
        _ => None,
    };
    match needed {
        Some(needed) if needed != super::layout_of(server_version) => Err(error!(
            ErrorCode::PqSignInUnavailable,
            "the server predates enrolling a security key this client creates"
        )),
        _ => Ok(()),
    }
}

fn out_of_order() -> NetworkError {
    error!(
        ErrorCode::PqSignInMalformed,
        "a management message out of order"
    )
}

/// The reply to one management message, in the `layout` its client reads. A failure is a
/// `Refused`, and drops the exchange.
pub(crate) async fn on_message<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    message: ManagementMessage,
    layout: SignInLayout,
) -> ManagementMessage {
    match handle(session, message, layout).await {
        Ok(reply) => reply,
        Err(err) => {
            inner_mut_state!(session.state_container)
                .connect_state
                .pq
                .manage = None;
            ManagementMessage::Done(ManagementDone::Refused(err.into_string()))
        }
    }
}

async fn handle<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    message: ManagementMessage,
    layout: SignInLayout,
) -> Result<ManagementMessage, NetworkError> {
    let cid = session
        .session_cid
        .get()
        .ok_or_else(|| error!(ErrorCode::StateImplicatedCidNotLoaded))?;
    let account_manager = &session.account_manager;
    let settings = account_manager.pq_settings().ok_or_else(|| {
        error!(
            ErrorCode::PqSignInUnavailable,
            "this server has no post-quantum sign-in settings"
        )
    })?;
    match message {
        ManagementMessage::Begin(begin) => {
            let cnac = account_manager
                .get_client_by_cid(cid)
                .await?
                .ok_or_else(|| NetworkError::msg("The session's account is gone"))?;
            if cnac.get_username() != begin.step_up.username {
                return Err(error!(
                    ErrorCode::PqSignInMalformed,
                    "a step-up for another account"
                ));
            }
            let record = cnac.auth_store().pq_record().cloned().ok_or_else(|| {
                error!(
                    ErrorCode::PqSignInUnavailable,
                    "the account has no post-quantum record"
                )
            })?;
            let scope = inner_state!(session.state_container).connect_state.pq.scope;
            // A step-up proves the account's factors again, so it is a guess like a sign-in's.
            if scope == SessionScope::Full {
                super::throttle::admit(session, &begin.step_up.username, Attempt::SignIn)?;
            }
            let (challenge, pending) =
                begin_management(settings, cid, &record, scope, begin, layout)?;
            inner_mut_state!(session.state_container)
                .connect_state
                .pq
                .manage = Some(ServerManagement::Pending(Box::new(pending)));
            Ok(ManagementMessage::Challenge(challenge))
        }
        ManagementMessage::Commit(commit) => match take(session) {
            Some(ServerManagement::Pending(pending)) => {
                match step_up_outcome(session, cid, pending.commit(&commit)).await? {
                    CommitStep::Ready(change) => apply(session, cid, change).await,
                    CommitStep::Enrol(challenge, enrolling) => {
                        inner_mut_state!(session.state_container)
                            .connect_state
                            .pq
                            .manage = Some(ServerManagement::Enrolling(enrolling));
                        Ok(ManagementMessage::EnrolChallenge(challenge))
                    }
                }
            }
            _ => Err(out_of_order()),
        },
        ManagementMessage::EnrolProof(proof) => match take(session) {
            Some(ServerManagement::Enrolling(enrolling)) => {
                apply(session, cid, enrolling.finish(&proof)?).await
            }
            _ => Err(out_of_order()),
        },
        _ => Err(out_of_order()),
    }
}

/// The throttle learns whether a full session's step-up proved the account's factors.
async fn step_up_outcome<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    committed: Result<CommitStep, NetworkError>,
) -> Result<CommitStep, NetworkError> {
    let scope = inner_state!(session.state_container).connect_state.pq.scope;
    let failed = matches!(&committed, Err(err) if err.code == ErrorCode::PqSignInFailed);
    if scope == SessionScope::Full && (committed.is_ok() || failed) {
        if let Some(username) = session.account_manager.get_username_by_cid(cid).await? {
            super::throttle::outcome(session, &username, Attempt::SignIn, committed.is_ok());
        }
    }
    committed
}

fn take<R: Ratchet, T: PlatformOps>(session: &CitadelSession<R, T>) -> Option<ServerManagement> {
    inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .manage
        .take()
}

async fn apply<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    change: Change,
) -> Result<ManagementMessage, NetworkError> {
    let outcome = session
        .account_manager
        .update_pq_record(cid, |record| change.apply(record, now_ms()))
        .await?;
    log::info!(target: "citadel", "Account {cid} changed its sign-in factors: {outcome:?}");
    Ok(ManagementMessage::Done(ManagementDone::Done(outcome)))
}
