//! Server: the sign-in management requests of an authenticated session, carried in
//! `PeerSignal::SignInManagement`. Every change is applied to the record as stored, under the
//! account manager's record lock.

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::messages::{ManagementDone, ManagementMessage};
use citadel_user::auth::pq::server::{
    begin_management, Change, CommitStep, PendingEnrol, PendingManagement,
};
use citadel_user::misc::now_ms;

/// Where a session's management exchange is.
pub(crate) enum ServerManagement {
    Pending(Box<PendingManagement>),
    Enrolling(PendingEnrol),
}

fn out_of_order() -> NetworkError {
    error!(
        ErrorCode::PqSignInMalformed,
        "a management message out of order"
    )
}

/// The reply to one management message. A failure is a `Refused`, and drops the exchange.
pub(crate) async fn on_message<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    message: ManagementMessage,
) -> ManagementMessage {
    match handle(session, message).await {
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
            let (challenge, pending) = begin_management(settings, cid, &record, scope, begin)?;
            inner_mut_state!(session.state_container)
                .connect_state
                .pq
                .manage = Some(ServerManagement::Pending(Box::new(pending)));
            Ok(ManagementMessage::Challenge(challenge))
        }
        ManagementMessage::Commit(commit) => match take(session) {
            Some(ServerManagement::Pending(pending)) => match pending.commit(&commit)? {
                CommitStep::Ready(change) => apply(session, cid, change).await,
                CommitStep::Enrol(challenge, enrolling) => {
                    inner_mut_state!(session.state_container)
                        .connect_state
                        .pq
                        .manage = Some(ServerManagement::Enrolling(enrolling));
                    Ok(ManagementMessage::EnrolChallenge(challenge))
                }
            },
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
