//! The connect exchange: the client's `AUTH_START`, the server's `AUTH_CHALLENGE`, and the client's
//! answer, which rides in connect STAGE0.

use super::packets::{self, Kind};
use super::runs_with;
use super::state::ServerPending;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::ConnectFail;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use crate::proto::session_resume;
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::client::{ClientLogin, ClientProof};
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{ChallengeBody, LoginChallenge, LoginProof, LoginStart};
use citadel_user::auth::pq::server::build_login_challenge;
use citadel_user::auth::pq::server::Expectation;
use citadel_user::client_account::{ClientNetworkAccount, PqAccountState};
use citadel_user::external_services::ServicesObject;

fn kind(aux: u8) -> Kind {
    Kind {
        primary: packet_flags::cmd::primary::DO_CONNECT,
        aux,
        algorithm: 0,
    }
}

/// Client, once pre-connect has finished: the `AUTH_START` to send in place of STAGE0, when the
/// server runs post-quantum sign-in and the caller offered factors. `None` keeps the legacy login.
pub(crate) fn begin<R: Ratchet>(
    state: &mut StateContainerInner<R>,
    ratchet: &R,
    server_version: u32,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<Option<BytesMut>, NetworkError> {
    let offered = state.connect_state.pq.offered.take();
    let Some(offered) = offered.filter(|_| runs_with(server_version)) else {
        return Ok(None);
    };
    let username = state
        .connect_state
        .proposed_credentials
        .as_ref()
        .map(|creds| creds.username().to_string())
        .ok_or_else(|| NetworkError::msg("Proposed credentials not loaded at AUTH_START"))?;
    let (start, client) = ClientLogin::start(&username, offered.password.as_ref(), None)?;
    let aux = packet_flags::cmd::aux::do_connect::AUTH_START;
    let packet = packets::craft(
        ratchet,
        kind(aux),
        &start,
        timestamp,
        security_level,
        ticket,
    )?;
    state.connect_state.pq.client = Some((start, client));
    state.connect_state.last_stage = aux;
    Ok(Some(packet))
}

/// Server: answers `AUTH_START` with a challenge, and remembers what STAGE0 must prove.
pub(crate) fn on_auth_start<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    ratchet: &R,
    payload: &[u8],
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    {
        let state = inner_state!(session.state_container);
        if state.connect_state.pq.server.is_some()
            || state.connect_state.last_stage == packet_flags::cmd::aux::do_connect::SUCCESS
        {
            log::warn!(target: "citadel", "Dropping a second AUTH_START for one session");
            return Ok(PrimaryProcessorResult::Void);
        }
    }
    let now = session.time_tracker.get_global_time_ns();
    let (challenge, pending) = match issue_challenge(session, cnac, ratchet.get_cid(), payload) {
        Ok(issued) => issued,
        Err(err) => {
            log::warn!(target: "citadel", "Refusing AUTH_START: {err}");
            let packet = failure(session, ratchet, err, now, security_level, ticket);
            return Ok(PrimaryProcessorResult::ReplyToSender(packet));
        }
    };
    let aux = packet_flags::cmd::aux::do_connect::AUTH_CHALLENGE;
    let packet = packets::craft(ratchet, kind(aux), &challenge, now, security_level, ticket)?;
    inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .server = Some(pending);
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

fn issue_challenge<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    cid: u64,
    payload: &[u8],
) -> Result<(LoginChallenge, ServerPending), NetworkError> {
    let start: LoginStart = packets::read(payload)?;
    let account = cnac.pq_account_state(&start.username);
    match session.account_manager.pq_settings() {
        Some(settings) => {
            let (challenge, expectation) =
                build_login_challenge(settings, account.as_account_auth(), &start)?;
            let pending = match expectation {
                Expectation::Factors(expected) => {
                    ServerPending::Factors(expected.bind(login_transcript(cid, &start, &challenge)))
                }
                Expectation::Legacy { upgrade } => ServerPending::Legacy(upgrade),
            };
            Ok((challenge, pending))
        }
        None if matches!(account, PqAccountState::PostQuantum(_)) => Err(citadel_io::error!(
            citadel_io::ErrorCode::PqSignInUnavailable,
            "this server has no post-quantum sign-in settings"
        )),
        None => {
            let legacy = LoginChallenge {
                server_nonce: [0u8; 32],
                body: ChallengeBody::Legacy { upgrade: None },
            };
            Ok((legacy, ServerPending::Legacy(None)))
        }
    }
}

fn failure<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    err: NetworkError,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> BytesMut {
    packet_crafter::do_connect::craft_final_status_packet(
        ratchet,
        false,
        None,
        ServicesObject::default(),
        err.to_string(),
        Vec::new(),
        timestamp,
        security_level,
        session.account_manager.get_backend_type(),
        ticket,
        None,
    )
}

/// Client: answers the challenge in connect STAGE0.
pub(crate) async fn on_auth_challenge<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    payload: &[u8],
    server_version: u32,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (pending, credentials) = {
        let mut state = inner_mut_state!(session.state_container);
        if state.connect_state.last_stage != packet_flags::cmd::aux::do_connect::AUTH_START {
            log::warn!(target: "citadel", "Dropping an AUTH_CHALLENGE that was not asked for");
            return Ok(PrimaryProcessorResult::Void);
        }
        (
            state.connect_state.pq.client.take(),
            state.connect_state.proposed_credentials.take(),
        )
    };
    let (start, client) = return_if_none!(pending, "AUTH_CHALLENGE without a login in flight");
    let credentials = return_if_none!(credentials, "Proposed creds not loaded");
    let cid = ratchet.get_cid();
    let challenge: LoginChallenge = match packets::read(payload) {
        Ok(challenge) => challenge,
        Err(err) => return fail_login(session, cid, err.into_string()),
    };
    let transcript = login_transcript(cid, &start, &challenge);
    let (proof, session_key) = match client.respond(&challenge, &transcript, None).await {
        Ok(ClientProof::Factors { proof, session_key }) => (Some(proof), Some(session_key)),
        Ok(ClientProof::Legacy { upgrade }) => (upgrade.map(LoginProof::Upgrade), None),
        Err(err) => return fail_login(session, cid, err.into_string()),
    };
    let resume_token =
        session_resume::exchanged_with(server_version, session.session_manager.resume_token(cid));
    let stage0 = packet_crafter::do_connect::craft_stage0_packet(
        ratchet,
        credentials,
        session.time_tracker.get_global_time_ns(),
        security_level,
        session.account_manager.get_backend_type(),
        ticket,
        resume_token,
        proof,
    )?;
    let mut state = inner_mut_state!(session.state_container);
    state.connect_state.pq.session_key = session_key;
    state.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
    Ok(PrimaryProcessorResult::ReplyToSender(stage0))
}

/// Client: a sign-in this side cannot complete ends the session, as a refused login does.
fn fail_login<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
    error_message: String,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::error!(target: "citadel", "Post-quantum sign-in could not complete: {error_message}");
    inner_mut_state!(session.state_container)
        .connect_state
        .on_fail();
    session.session_cid.set(None);
    session.state.set(SessionState::NeedsConnect);
    session.disable_dc_signal();
    session.send_to_kernel(NodeResult::ConnectFail(ConnectFail {
        ticket: session.kernel_ticket.get(),
        cid_opt: Some(cid),
        error_message,
    }))?;
    Ok(PrimaryProcessorResult::EndSession(
        "Post-quantum sign-in could not complete",
    ))
}
