//! The connect exchange: the client's `AUTH_START`, the server's `AUTH_CHALLENGE`, and the client's
//! answer, which rides in connect STAGE0.

use super::packets::{self, Kind};
use super::refusal::{fail_login, failure};
use super::security_key::SecurityKeyPurpose;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use crate::proto::session_resume::ResumeToken;
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::admission;
use citadel_user::auth::pq::client::{ClientLogin, ClientProof, RecoveryOffer, RelyingParty};
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{LoginProof, LoginStart};
use citadel_user::auth::pq::throttle::Attempt;
use citadel_user::client_account::ClientNetworkAccount;

fn kind(aux: u8) -> Kind {
    Kind {
        primary: packet_flags::cmd::primary::DO_CONNECT,
        aux,
        algorithm: 0,
    }
}

/// Client, once pre-connect has finished: the `AUTH_START` to send in place of STAGE0, when the
/// caller offered factors. `None` keeps the legacy login.
pub(crate) fn begin<R: Ratchet>(
    state: &mut StateContainerInner<R>,
    ratchet: &R,
    resume: Option<ResumeToken>,
    server_version: u32,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<Option<BytesMut>, NetworkError> {
    let Some(offered) = state.connect_state.pq.offered.take() else {
        return Ok(None);
    };
    let username = state
        .connect_state
        .proposed_credentials
        .as_ref()
        .map(|creds| creds.username().to_string())
        .ok_or_else(|| NetworkError::msg("Proposed credentials not loaded at AUTH_START"))?;
    let recovery = match (&offered.recovery_code, &offered.recovery_phrase) {
        (Some(_), Some(_)) => {
            return Err(error!(
                ErrorCode::PqSignInMalformed,
                "a sign-in offering both a recovery code and a recovery phrase"
            ))
        }
        // A server below it would answer a phrase with a decoy: say why instead.
        (None, Some(_)) if !super::recover::server_recovers(Some(server_version)) => {
            return Err(error!(ErrorCode::RecoveryUnsupported))
        }
        (None, Some(phrase)) => Some(RecoveryOffer::Phrase(phrase)),
        (Some(code), None) => Some(RecoveryOffer::Code(code)),
        (None, None) => None,
    };
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
        // Before the challenge: a throttled guess or a refused bot costs the server a lookup
        // or one call, not an OPRF evaluation and an encapsulation.
        Ok(start) => {
            let attempt = match start.recovery {
                Some(_) => Attempt::Recovery,
                None => Attempt::SignIn,
            };
            if let Err(err) = super::throttle::admit(session, &start.username, attempt) {
                return refuse(session, ratchet, err, now, security_level, ticket);
            }
            inner_mut_state!(session.state_container)
                .connect_state
                .pq
                .attempt = Some(attempt);
            let ctx = super::admission::sign_in(session, cnac.get_cid(), &start).await;
            let policy = super::admission::policy(session);
            admission::then(policy.as_ref(), ctx, || {
                super::challenge::issue(session, cnac, ratchet.get_cid(), &start)
            })
            .await
        }
        Err(err) => Err(err),
    };
    let (challenge, pending) = match issued {
        Ok(issued) => issued,
        Err(err) => return refuse(session, ratchet, err, now, security_level, ticket),
    };
    let aux = packet_flags::cmd::aux::do_connect::AUTH_CHALLENGE;
    let packet = packets::craft(ratchet, kind(aux), &challenge, now, security_level, ticket)?;
    inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .server = Some(pending);
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

fn refuse<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    err: NetworkError,
    now: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::warn!(target: "citadel", "Refusing AUTH_START: {err}");
    let packet = failure(session, ratchet, err, now, security_level, ticket);
    session.release_provisional_slot();
    Ok(PrimaryProcessorResult::EndSessionAndReplyToSender(
        packet,
        "Login refused",
    ))
}

/// Client: answers the challenge in connect STAGE0.
pub(crate) async fn on_auth_challenge<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    payload: &[u8],
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
    let sent = match super::challenge::read(payload) {
        Ok(sent) => sent,
        Err(err) => return fail_login(session, cid, err.into_string()),
    };
    let transcript = login_transcript(cid, &start, &sent);
    let request =
        ClientLogin::security_key_request(&sent.challenge, RelyingParty::of_sign_in(&sent));
    let challenge = sent.challenge;
    let request = match request {
        Ok(request) => request,
        Err(err) => return fail_login(session, cid, err.into_string()),
    };
    let key = match request {
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
    let resume_token = session.session_manager.resume_token(cid);
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
