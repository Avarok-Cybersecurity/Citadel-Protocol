//! The server's side of the recovery lane: throttle and admission before any work, a challenge to
//! the one recovery factor the start names (or a decoy), and, once its proof verifies, this
//! exchange's ratchet installed as the account's bundle in place of every other device's.

use super::super::packets;
use super::client::kind;
use super::state::ServerRecover;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use bytes::BytesMut;
use citadel_crypt::prelude::Toolset;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::admission::{self, AdmissionContext, AdmissionKind};
use citadel_user::auth::pq::messages::{
    AuthChallenge, ChallengeCeremony, RecoverDone, RecoverProof, RecoverStart,
};
use citadel_user::auth::pq::recover_transcript;
use citadel_user::auth::pq::server::{build_recovery_challenge, MAX_LABEL_CHARS};
use citadel_user::auth::pq::throttle::Attempt;

/// Every refusal after the start was read: the same failure a wrong phrase gets.
fn failed() -> NetworkError {
    error!(ErrorCode::PqSignInFailed)
}

/// Server: answers `RECOVER_START` with the recovery factor's challenge.
pub(crate) async fn on_start<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    payload: &[u8],
    algorithm: u8,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<BytesMut, NetworkError> {
    let start: RecoverStart = packets::read(payload)?;
    let username = start.login.username.clone();
    let cid = ratchet.get_cid();
    let account_cid = session
        .account_manager
        .get_persistence_handler()
        .get_cid_by_username(&username);
    if account_cid != cid {
        return Err(error!(
            ErrorCode::PqSignInMalformed,
            "a recovery for another account"
        ));
    }
    let label = start.device.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err(error!(ErrorCode::PqSignInMalformed, "a device label"));
    }
    let account_manager = &session.account_manager;
    let settings = account_manager
        .pq_settings()
        .ok_or_else(|| error!(ErrorCode::RecoveryUnsupported))?;
    super::super::throttle::admit(session, &username, Attempt::Recovery)?;
    let source = Some(session.remote_peer.ip());
    let ctx = AdmissionContext {
        username: username.clone(),
        kind: AdmissionKind::Recover,
        token: start.login.admission.clone(),
        remote_addr: source,
    };
    let policy = super::super::admission::policy(session);
    admission::check(policy.as_ref(), ctx).await?;
    let record = account_manager
        .get_client_by_username(&username)
        .await?
        .and_then(|cnac| cnac.auth_store().pq_record().cloned());
    let (challenge, expected) = build_recovery_challenge(settings, record.as_ref(), &start.login)?;
    let challenge = AuthChallenge {
        challenge,
        ceremony: Some(ChallengeCeremony {
            rp_id: settings.security_key_rp_id().map(str::to_owned),
        }),
    };
    let mut state = inner_mut_state!(session.state_container);
    let recover = &mut state.register_state.pq.recover;
    let binding = recover
        .binding
        .ok_or_else(|| NetworkError::msg("The key exchange's binding was not kept"))?;
    let transcript = recover_transcript(cid, &binding, &start, &challenge);
    recover.pending = Some(ServerRecover {
        pending: expected.bind(transcript),
        username,
    });
    let aux = packet_flags::cmd::aux::do_register::RECOVER_CHALLENGE;
    let now = session.time_tracker.get_global_time_ns();
    packets::craft(
        ratchet,
        kind(aux, algorithm),
        &challenge,
        now,
        security_level,
        ticket,
    )
}

/// Server: checks `RECOVER_PROOF`; on success, ends the account's live session, spends the
/// factor and installs this exchange's ratchet as the account's only bundle.
pub(crate) async fn on_proof<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    payload: &[u8],
    algorithm: u8,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<BytesMut, NetworkError> {
    let ServerRecover { pending, username } = inner_mut_state!(session.state_container)
        .register_state
        .pq
        .recover
        .pending
        .take()
        .ok_or_else(|| NetworkError::msg("RECOVER_PROOF without a challenge in flight"))?;
    let proof: RecoverProof = packets::read(payload)?;
    let account_manager = &session.account_manager;
    let verified = pending.verify(&proof.finish);
    super::super::throttle::outcome(session, &username, Attempt::Recovery, verified.is_ok());
    let verified = verified?;
    let cid = ratchet.get_cid();
    session
        .session_manager
        .displace_session_for_authenticated_login(cid, true, None)
        .await
        .map_err(NetworkError::msg)?;
    let cnac = account_manager
        .recover_pq_account(cid, &verified.used, Toolset::new(cid, ratchet.clone()))
        .await
        .map_err(|_| failed())?;
    log::warn!(target: "citadel", "Account {cid} was recovered on a new device; every other device's bundle is revoked");
    let done = RecoverDone {
        cid,
        full_name: cnac.auth_store().full_name().to_string(),
    };
    let aux = packet_flags::cmd::aux::do_register::RECOVER_DONE;
    let now = session.time_tracker.get_global_time_ns();
    packets::craft(
        ratchet,
        kind(aux, algorithm),
        &done,
        now,
        security_level,
        ticket,
    )
}
