//! Server: the sign-in management requests of an authenticated session, carried in
//! `PeerSignal::SignInManagement`. Every change is applied to the record as stored, under the
//! account manager's record lock.

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::messages::{ManagementDone, ManagementMessage};
use citadel_user::auth::pq::resume::PresentedResume;
use citadel_user::auth::pq::server::{
    begin_management, reissue_grant, Change, CommitStep, PendingEnrol, PendingManagement,
};
use citadel_user::auth::pq::throttle::Attempt;
use citadel_user::misc::now_ms;

/// Where a session's management exchange is.
pub(crate) enum ServerManagement {
    Pending(Box<PendingManagement>),
    /// With the resume credential the commit carried, for when the key has proven itself.
    Enrolling(PendingEnrol, Option<Box<PresentedResume>>),
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
            // A step-up proves the account's factors again, so it is a guess like a sign-in's.
            if scope == SessionScope::Full {
                super::throttle::admit(session, &begin.step_up.username, Attempt::SignIn)?;
            }
            let (challenge, pending) = begin_management(settings, cid, &record, scope, begin)?;
            inner_mut_state!(session.state_container)
                .connect_state
                .pq
                .manage = Some(ServerManagement::Pending(Box::new(pending)));
            Ok(ManagementMessage::Challenge(challenge))
        }
        ManagementMessage::Commit(commit) => match take(session) {
            Some(ServerManagement::Pending(pending)) => {
                let held = commit.ceremony.resume.clone().map(Box::new);
                match step_up_outcome(session, cid, pending.commit(&commit)).await? {
                    CommitStep::Ready(change) => apply(session, cid, change, held).await,
                    CommitStep::Enrol(challenge, enrolling) => {
                        inner_mut_state!(session.state_container)
                            .connect_state
                            .pq
                            .manage = Some(ServerManagement::Enrolling(enrolling, held));
                        Ok(ManagementMessage::EnrolChallenge(challenge))
                    }
                }
            }
            _ => Err(out_of_order()),
        },
        ManagementMessage::EnrolProof(proof) => match take(session) {
            Some(ServerManagement::Enrolling(enrolling, held)) => {
                apply(session, cid, enrolling.finish(&proof)?, held).await
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
    held: Option<Box<PresentedResume>>,
) -> Result<ManagementMessage, NetworkError> {
    let account_manager = &session.account_manager;
    let settings = account_manager.pq_settings();
    let full = inner_state!(session.state_container).connect_state.pq.scope == SessionScope::Full;
    let (outcome, grant) = account_manager
        .update_pq_record(cid, |record| {
            let before = record.clone();
            let now = now_ms();
            let outcome = change.apply(record, now)?;
            // A full session that changed its own account's sign-in keeps the resume credential
            // its device holds, bound to the account as it now stands and expiring when it did.
            let grant = match (settings, &held) {
                (Some(settings), Some(held)) if full => {
                    reissue_grant(settings, cid, &before, record, held, now)
                }
                _ => None,
            };
            Ok((outcome, grant))
        })
        .await?;
    log::info!(target: "citadel", "Account {cid} changed its sign-in factors: {outcome:?}");
    Ok(ManagementMessage::Done(match grant {
        Some(grant) => ManagementDone::Reissued { outcome, grant },
        None => ManagementDone::Done(outcome),
    }))
}
