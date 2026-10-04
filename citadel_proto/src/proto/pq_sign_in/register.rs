//! The register exchange: after the key exchange (STAGE1), the client's `PQ_START` and the
//! server's `PQ_REPLY`; the client's keys then ride in STAGE2.

use super::packets::{self, Kind};
use super::runs_with;
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
use citadel_user::auth::pq::client::ClientRegistration;
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
/// STAGE2, when the server runs post-quantum sign-in and the caller gave a password.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    server_version: u32,
    username: &str,
    algorithm: u8,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<Option<BytesMut>, NetworkError> {
    let mut state = inner_mut_state!(session.state_container);
    let password = state.register_state.pq.password.take();
    let Some(password) = password.filter(|_| runs_with(server_version)) else {
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
    payload: &[u8],
    algorithm: u8,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let reply = match reply_to(session, payload).await {
        Ok(reply) => reply,
        Err(err) => {
            log::warn!(target: "citadel", "Refusing PQ_START: {err}");
            let packet = packet_crafter::do_register::craft_failure(
                algorithm,
                session.time_tracker.get_global_time_ns(),
                err.into_string(),
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
    payload: &[u8],
) -> Result<RegStartReply, NetworkError> {
    let start: RegStart = packets::read(payload)?;
    // The OPRF runs only once the admission check has passed: a refused bot costs one call.
    let ctx = super::admission::register(session, &start.username, start.admission.clone());
    let policy = super::admission::policy(session);
    let settings = session.account_manager.pq_settings();
    let reply = admission::then(policy.as_ref(), Some(ctx), false, || {
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
) -> Result<Option<citadel_user::auth::pq::messages::RegFinish>, NetworkError> {
    let reply: RegStartReply = packets::read(payload)?;
    let client = inner_mut_state!(session.state_container)
        .register_state
        .pq
        .client
        .take()
        .ok_or_else(|| NetworkError::msg("PQ_REPLY without a registration in flight"))?;
    match reply {
        RegStartReply::Accepted(reply) => {
            let (finish, codes) = client.finish(&reply, true).await?;
            let mut state = inner_mut_state!(session.state_container);
            state.register_state.pq.registered = true;
            state.register_state.pq.recovery_codes = codes
                .iter()
                .map(|code| code.display().to_string())
                .collect();
            Ok(Some(finish))
        }
        RegStartReply::Unsupported => Ok(None),
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
