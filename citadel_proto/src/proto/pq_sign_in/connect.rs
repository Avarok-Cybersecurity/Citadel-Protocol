//! The connect exchange: the client's `AUTH_START`, the server's `AUTH_CHALLENGE`, and the client's
//! answer, which rides in connect STAGE0.

use super::packets::{self, Kind};
use super::refusal::{fail_login, failure};
use super::runs_with;
use super::security_key::SecurityKeyPurpose;
use super::state::ServerPending;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use crate::proto::session_resume::{self, ResumeToken};
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::admission;
use citadel_user::auth::pq::client::{ClientLogin, ClientProof};
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{ChallengeBody, LoginChallenge, LoginProof, LoginStart};
use citadel_user::auth::pq::server::build_login_challenge;
use citadel_user::auth::pq::server::Expectation;
use citadel_user::client_account::{ClientNetworkAccount, PqAccountState};

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
    resume: Option<ResumeToken>,
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
    let recovery = offered.recovery_code.as_ref();
    let (mut start, client) = ClientLogin::start(&username, offered.password.as_ref(), recovery)?;
    start.admission = offered.admission.clone();
    start.resume = resume.map(ResumeToken::to_bytes);
    if recovery.is_some() {
        state.connect_state.pq.scope = SessionScope::Recovery;
    }
    let aux = packet_flags::cmd::aux::do_connect::AUTH_START;
    let packet = packets::craft(
        ratchet,
        kind(aux),
        &start,
        timestamp,
        security_level,
        ticket,
    )?;
    state.connect_state.pq.client = Some((start, client, offered.security_key));
    state.connect_state.last_stage = aux;
    Ok(Some(packet))
}

/// Server: answers `AUTH_START` with a challenge, and remembers what STAGE0 must prove.
pub(crate) async fn on_auth_start<R: Ratchet, T: PlatformOps>(
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
    let issued = match packets::read::<LoginStart>(payload) {
        // Before the challenge: a refused bot costs the server one call, not an OPRF
        // evaluation and an encapsulation.
        Ok(start) => {
            let ctx = super::admission::sign_in(session, cnac.get_cid(), &start);
            let policy = super::admission::policy(session);
            admission::then(policy.as_ref(), ctx, false, || {
                issue_challenge(session, cnac, ratchet.get_cid(), &start)
            })
            .await
        }
        Err(err) => Err(err),
    };
    let (challenge, pending) = match issued {
        Ok(issued) => issued,
        Err(err) => {
            log::warn!(target: "citadel", "Refusing AUTH_START: {err}");
            let packet = failure(session, ratchet, err, now, security_level, ticket);
            session.release_provisional_slot();
            return Ok(PrimaryProcessorResult::EndSessionAndReplyToSender(
                packet,
                "Login refused",
            ));
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
    start: &LoginStart,
) -> Result<(LoginChallenge, ServerPending), NetworkError> {
    let account = cnac.pq_account_state(&start.username);
    match session.account_manager.pq_settings() {
        Some(settings) => {
            let (challenge, expectation) =
                build_login_challenge(settings, account.as_account_auth(), start)?;
            if ClientLogin::security_key_request(&challenge).is_some() {
                super::presence::open(session);
            }
            let pending = match expectation {
                Expectation::Factors(expected) => {
                    ServerPending::Factors(expected.bind(login_transcript(cid, start, &challenge)))
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
    let (start, client, security_key) =
        return_if_none!(pending, "AUTH_CHALLENGE without a login in flight");
    let credentials = return_if_none!(credentials, "Proposed creds not loaded");
    let cid = ratchet.get_cid();
    let challenge: LoginChallenge = match packets::read(payload) {
        Ok(challenge) => challenge,
        Err(err) => return fail_login(session, cid, err.into_string()),
    };
    let transcript = login_transcript(cid, &start, &challenge);
    let key = match ClientLogin::security_key_request(&challenge) {
        Some(request) => match security_key {
            Some(security_key) => {
                super::presence::open(session);
                match security_key.ask(SecurityKeyPurpose::SignIn, request).await {
                    Ok(answer) => Some(answer),
                    Err(err) => return fail_login(session, cid, err.into_string()),
                }
            }
            // No key to offer: prove what the client has, and let the policy decide.
            None => None,
        },
        None => None,
    };
    let (proof, session_key) = match client.respond(&challenge, &transcript, key).await {
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
