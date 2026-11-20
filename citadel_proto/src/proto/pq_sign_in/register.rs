//! The register exchange: after the key exchange (STAGE1), the client's `PQ_START` and the
//! server's `PQ_REPLY`; the client's keys then ride in STAGE2.

use super::packets::{self, Kind};
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use bytes::BytesMut;
use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::pq::admission;
use citadel_user::auth::pq::client::{ClientRegistration, NewRecovery};
use citadel_user::auth::pq::messages::RegFinish;
use citadel_user::auth::pq::messages::{RegStart, RegStartReply};
use citadel_user::auth::pq::server::{registration_reply, PendingRegistration};
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::misc::{now_ms, AccountError};
use citadel_user::prelude::ConnectionInfo;

fn kind(aux: u8, algorithm: u8) -> Kind {
    Kind {
        primary: packet_flags::cmd::primary::DO_REGISTER,
        aux,
        algorithm,
    }
}

/// Client, once STAGE1 has given it the session ratchet: the `PQ_START` to send in place of
/// STAGE2, when the caller gave a password.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    username: &str,
    algorithm: u8,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<Option<BytesMut>, NetworkError> {
    let mut state = inner_mut_state!(session.state_container);
    let Some(password) = state.register_state.pq.password.take() else {
        return Ok(None);
    };
    let (mut start, client) = ClientRegistration::start(username, &password)?;
    start.admission = state.register_state.pq.admission.take();
    let aux = packet_flags::cmd::aux::do_register::PQ_START;
    let packet = packets::craft(
        ratchet,
        kind(aux, algorithm),
        &start,
        timestamp,
        security_level,
        ticket,
    )?;
    state.register_state.pq.client = Some(client);
    Ok(Some(packet))
}

/// Server: evaluates the OPRF and hands out the salts, or says it cannot.
pub(crate) async fn on_pq_start<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    client_version: u32,
    payload: &[u8],
    algorithm: u8,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (reads_challenge, replied) = match packets::read::<RegStart>(payload) {
        Ok(start) => (start.reads_challenge, reply_to(session, start).await),
        Err(err) => (false, Err(err)),
    };
    let reply = match replied {
        Ok(reply) => reply,
        Err(err) => {
            log::warn!(target: "citadel", "Refusing PQ_START: {err}");
            let packet = packet_crafter::do_register::craft_failure(
                algorithm,
                session.time_tracker.get_global_time_ns(),
                super::refusal::register_failure(
                    err,
                    reads_challenge,
                    super::recover::server_recovers(Some(client_version)),
                ),
                ratchet.get_cid(),
                ticket,
            );
            session.release_provisional_slot();
            return Ok(PrimaryProcessorResult::EndSessionAndReplyToSender(
                packet,
                "PQ_START refused",
            ));
        }
    };
    let packet = packets::craft(
        ratchet,
        kind(packet_flags::cmd::aux::do_register::PQ_REPLY, algorithm),
        &reply,
        session.time_tracker.get_global_time_ns(),
        security_level,
        ticket,
    )?;
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

async fn reply_to<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    start: RegStart,
) -> Result<RegStartReply, NetworkError> {
    // The OPRF runs only once the admission check has passed: a refused bot costs one call.
    let ctx = super::admission::register(session, &start.username, start.admission.clone());
    let policy = super::admission::policy(session);
    let settings = session.account_manager.pq_settings();
    let reply = admission::then(policy.as_ref(), Some(ctx), || {
        settings
            .map(|settings| registration_reply(settings, &start))
            .transpose()
    })
    .await?;
    let mut state = inner_mut_state!(session.state_container);
    state.register_state.pq.admitted = true;
    match reply {
        Some((reply, pending)) => {
            state.register_state.pq.server = Some(pending);
            Ok(RegStartReply::Accepted(reply))
        }
        None => Ok(RegStartReply::Unsupported),
    }
}

/// Client: what STAGE2 carries after the server's reply. `None` registers the legacy way, for a
/// server that has no post-quantum settings.
pub(crate) async fn on_pq_reply<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    payload: &[u8],
    server_version: u32,
) -> Result<Option<citadel_user::auth::pq::messages::RegFinish>, NetworkError> {
    let reply: RegStartReply = packets::read(payload)?;
    let (client, domain, username) = {
        let mut state = inner_mut_state!(session.state_container);
        let username = state
            .connect_state
            .proposed_credentials
            .as_ref()
            .map(|creds| creds.username().to_string())
            .ok_or_else(|| NetworkError::msg("PQ_REPLY without the registration's username"))?;
        let pq = &mut state.register_state.pq;
        let client = pq
            .client
            .take()
            .ok_or_else(|| NetworkError::msg("PQ_REPLY without a registration in flight"))?;
        (client, pq.recovery_domain.take(), username)
    };
    match reply {
        RegStartReply::Accepted(reply) => {
            let recovery = new_recovery(server_version, domain.as_deref(), &username);
            let (finish, issued) = client.finish(&reply, recovery).await?;
            let mut state = inner_mut_state!(session.state_container);
            let pq = &mut state.register_state.pq;
            pq.registered = true;
            pq.recovery_codes = issued
                .codes
                .iter()
                .map(|code| code.display().to_string())
                .collect();
            pq.recovery_phrase = issued.phrase.map(|seed| seed.words());
            Ok(Some(finish))
        }
        RegStartReply::Unsupported => Ok(None),
    }
}

/// What a new account is given: the phrase at a server that recovers accounts, given its domain
/// (nothing without one), and the ten codes it always had at an older server, which could not
/// store a phrase.
pub(crate) fn new_recovery<'a>(
    server_version: u32,
    domain: Option<&'a str>,
    username: &'a str,
) -> NewRecovery<'a> {
    match domain {
        _ if !super::recover::server_recovers(Some(server_version)) => NewRecovery::Codes,
        Some(canonical_domain) => NewRecovery::Phrase {
            username,
            canonical_domain,
        },
        None => NewRecovery::None,
    }
}

/// Server: the account a post-quantum STAGE2 creates. The names come from STAGE2's credentials,
/// which must name the user `PQ_START` named.
pub(crate) async fn create_account<R: Ratchet>(
    account_manager: &AccountManager<R, R>,
    pending: Option<PendingRegistration>,
    finish: RegFinish,
    credentials: ProposedCredentials,
    conn_info: ConnectionInfo,
    session_crypto_state: PeerSessionCrypto<R>,
) -> Result<ClientNetworkAccount<R, R>, AccountError> {
    let pending = pending.ok_or_else(|| {
        citadel_io::error!(
            citadel_io::ErrorCode::PqSignInMalformed,
            "a STAGE2 without PQ_START"
        )
    })?;
    if credentials.username() != pending.username() {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::PqSignInMalformed,
            "a STAGE2 for another username"
        ));
    }
    let (username, _, full_name, _) = credentials.decompose();
    let record = pending.finish(finish, now_ms())?;
    account_manager
        .register_pq_client_network_account(
            conn_info,
            username,
            full_name,
            record,
            session_crypto_state,
        )
        .await
}
