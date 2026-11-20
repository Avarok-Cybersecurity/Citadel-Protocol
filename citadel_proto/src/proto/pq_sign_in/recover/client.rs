//! The recovering device's side: `RECOVER_START` once STAGE1 has given it a ratchet, the proof
//! once the challenge comes, and the new bundle saved once the server says it is installed.

use super::super::packets::{self, Kind};
use super::state::ClientRecover;
use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::RecoverOkay;
use crate::proto::packet::packet_flags;
use crate::proto::packet_processor::includes::*;
use bytes::BytesMut;
use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::prelude::Toolset;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::client::{ClientLogin, ClientProof, RecoveryOffer};
use citadel_user::auth::pq::messages::{
    AuthChallenge, DeviceOffer, LoginProof, RecoverDone, RecoverProof, RecoverStart,
};
use citadel_user::auth::pq::{channel_binding, recover_transcript};
use citadel_user::prelude::ConnectionInfo;

pub(super) fn kind(aux: u8, algorithm: u8) -> Kind {
    Kind {
        primary: packet_flags::cmd::primary::DO_REGISTER,
        aux,
        algorithm,
    }
}

/// Client, at STAGE0: keeps the payload it sent, which the recovery is bound to.
pub(crate) fn on_stage0_sent<R: Ratchet>(
    state: &mut crate::proto::state_container::StateContainerInner<R>,
    stage0_packet: &[u8],
) {
    let recover = &mut state.register_state.pq.recover;
    if recover.ask.is_some() {
        recover.sent_stage0 = Some(stage0_packet[HDP_HEADER_BYTE_LEN..].to_vec());
    }
}

/// Client, once STAGE1 has given it the ratchet: the `RECOVER_START` to send in place of STAGE2,
/// when this session recovers. Refused, before anything is sent, by a server below
/// `RECOVERY_SINCE`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    server_version: u32,
    stage1_payload: &[u8],
    algorithm: u8,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<Option<BytesMut>, NetworkError> {
    let mut state = inner_mut_state!(session.state_container);
    let recover = &mut state.register_state.pq.recover;
    let Some(ask) = recover.ask.take() else {
        return Ok(None);
    };
    if !super::server_recovers(Some(server_version)) {
        return Err(error!(ErrorCode::RecoveryUnsupported));
    }
    let sent_stage0 = recover
        .sent_stage0
        .take()
        .ok_or_else(|| NetworkError::msg("The recovery's STAGE0 was not kept"))?;
    let binding = channel_binding(&sent_stage0, stage1_payload);
    let offer = Some(RecoveryOffer::Phrase(&ask.phrase));
    let (mut login, client) = ClientLogin::start(&ask.username, None, offer)?;
    login.admission = ask.admission;
    let start = RecoverStart {
        login,
        device: DeviceOffer {
            label: ask.device_label,
        },
    };
    let aux = packet_flags::cmd::aux::do_register::RECOVER_START;
    let kind = kind(aux, algorithm);
    let packet = packets::craft(ratchet, kind, &start, timestamp, security_level, ticket)?;
    recover.username = Some(ask.username);
    recover.proving = Some(ClientRecover {
        start,
        login: client,
        binding,
    });
    Ok(Some(packet))
}

/// Client: proves the challenged factor in `RECOVER_PROOF`.
pub(crate) async fn on_challenge<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    payload: &[u8],
    algorithm: u8,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<BytesMut, NetworkError> {
    let proving = inner_mut_state!(session.state_container)
        .register_state
        .pq
        .recover
        .proving
        .take()
        .ok_or_else(|| NetworkError::msg("RECOVER_CHALLENGE without a recovery in flight"))?;
    let challenge: AuthChallenge = packets::read(payload)?;
    let cid = ratchet.get_cid();
    let transcript = recover_transcript(cid, &proving.binding, &proving.start, &challenge);
    let finish = match proving
        .login
        .respond(&challenge.challenge, &transcript, None)
        .await?
    {
        ClientProof::Factors {
            proof: LoginProof::Factors(finish),
            ..
        } => finish,
        _ => return Err(error!(ErrorCode::PqSignInMalformed, "a recovery challenge")),
    };
    let aux = packet_flags::cmd::aux::do_register::RECOVER_PROOF;
    let now = session.time_tracker.get_global_time_ns();
    let proof = RecoverProof { finish };
    packets::craft(
        ratchet,
        kind(aux, algorithm),
        &proof,
        now,
        security_level,
        ticket,
    )
}

/// Client: the server installed this exchange's ratchet as the account's bundle; this device
/// keeps it as its own, replacing any it had for the account.
pub(crate) async fn on_done<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: R,
    payload: &[u8],
    remote_addr: SocketAddr,
) -> Result<u64, NetworkError> {
    let done: RecoverDone = packets::read(payload)?;
    let cid = ratchet.get_cid();
    if done.cid != cid {
        return Err(error!(
            ErrorCode::PqSignInMalformed,
            "a recovery for another account"
        ));
    }
    let username = inner_mut_state!(session.state_container)
        .register_state
        .pq
        .recover
        .username
        .take()
        .ok_or_else(|| NetworkError::msg("RECOVER_DONE without a recovery in flight"))?;
    let crypto = PeerSessionCrypto::new(Toolset::new(cid, ratchet), true);
    let account_manager = &session.account_manager;
    let conn_info = ConnectionInfo { addr: remote_addr };
    let cnac = account_manager
        .recover_personal_pq_server(cid, username, done.full_name, crypto, conn_info)
        .await?;
    if let Some(endpoint) = session.endpoint_to_persist.as_ref() {
        crate::proto::misc::server_endpoint_store::store(account_manager, cid, endpoint).await?;
    }
    session
        .session_manager
        .clear_provisional_session(&session.provisional_key, session.init_time);
    session
        .send_to_kernel(NodeResult::RecoverOkay(RecoverOkay {
            ticket: session.kernel_ticket.get(),
            cid: cnac.get_cid(),
        }))
        .map_err(|err| NetworkError::msg(err.to_string()))?;
    Ok(cid)
}
