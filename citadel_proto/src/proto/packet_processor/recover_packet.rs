//! The recovery lane's packets (see `pq_sign_in::recover`): the `DO_REGISTER` stages after
//! STAGE1 that recover an account instead of creating one. Each stage is accepted only in its
//! turn and only by the side it is addressed to, and opens only under the exchange's ratchet.

use super::includes::*;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::RegisterFailure;
use crate::proto::pq_sign_in::recover::{client, server};
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;

use packet_flags::cmd::aux::do_register::{
    RECOVER_CHALLENGE, RECOVER_DONE, RECOVER_PROOF, RECOVER_START, STAGE1,
};

/// Whether `aux` is one of the lane's stages.
pub(super) fn is_recovery_stage(aux: u8) -> bool {
    (RECOVER_START..=RECOVER_DONE).contains(&aux)
}

pub(super) async fn process<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    header: &Ref<&[u8], HdpHeader>,
    payload: BytesMut,
    remote_addr: SocketAddr,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let aux = header.cmd_aux;
    let expected = match (aux, session.is_server) {
        (RECOVER_START, true) => STAGE1,
        (RECOVER_CHALLENGE, false) => RECOVER_START,
        (RECOVER_PROOF, true) => RECOVER_CHALLENGE,
        (RECOVER_DONE, false) => RECOVER_PROOF,
        _ => {
            log::warn!(target: "citadel", "Dropping recovery stage {aux} sent to the wrong side");
            return Ok(PrimaryProcessorResult::Void);
        }
    };
    let ratchet = {
        let state = inner_state!(session.state_container);
        let register = &state.register_state;
        // A registration in flight (`PQ_START` answered) is not a recovery.
        let in_turn = register.last_stage == expected && register.pq.server.is_none();
        if !in_turn {
            log::warn!(target: "citadel", "Dropping recovery stage {aux} out of order");
            return Ok(PrimaryProcessorResult::Void);
        }
        return_if_none!(
            register.created_ratchet.clone(),
            "No ratchet for a recovery"
        )
    };
    let (_, plaintext) = return_if_none!(
        validation::aead::validate_custom(&ratchet, &header.bytes(), payload),
        "Unable to open a recovery stage"
    );
    let algorithm = header.algorithm;
    let level = header.security_level.into();
    let ticket = Ticket::from(header.context_info.get());
    let replied = match aux {
        RECOVER_START => server::on_start(session, &ratchet, &plaintext, algorithm, level, ticket)
            .await
            .map(|packet| (packet, RECOVER_CHALLENGE)),
        RECOVER_CHALLENGE => {
            client::on_challenge(session, &ratchet, &plaintext, algorithm, level, ticket)
                .await
                .map(|packet| (packet, RECOVER_PROOF))
        }
        RECOVER_PROOF => server::on_proof(session, &ratchet, &plaintext, algorithm, level, ticket)
            .await
            .map(|packet| (packet, RECOVER_DONE)),
        _ => {
            return match client::on_done(session, ratchet, &plaintext, remote_addr).await {
                Ok(cid) => {
                    log::info!(target: "citadel", "This device now holds account {cid}'s bundle");
                    session.shutdown();
                    Ok(PrimaryProcessorResult::Void)
                }
                Err(err) => fail_client(session, err),
            }
        }
    };
    match replied {
        Ok((packet, stage)) => {
            let mut state = inner_mut_state!(session.state_container);
            state.register_state.last_stage = stage;
            state.register_state.on_register_packet_received();
            Ok(PrimaryProcessorResult::ReplyToSender(packet))
        }
        Err(err) if session.is_server => refuse(session, header, err, ticket),
        Err(err) => fail_client(session, err),
    }
}

/// Server: a recovery that cannot go on ends with a registration FAILURE. A wrong or foreign
/// phrase, an unknown name, a throttled attempt and a failed install all read `PqSignInFailed`;
/// an admission refusal carries its own code and challenge, so the client can show the check.
fn refuse<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    header: &Ref<&[u8], HdpHeader>,
    err: NetworkError,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::warn!(target: "citadel", "Refusing a recovery: {err}");
    inner_mut_state!(session.state_container)
        .register_state
        .on_fail();
    let packet = packet_crafter::do_register::craft_failure(
        header.algorithm,
        session.time_tracker.get_global_time_ns(),
        crate::proto::pq_sign_in::refusal::register_failure(err, true, true),
        header.session_cid.get(),
        ticket,
    );
    session.release_provisional_slot();
    Ok(PrimaryProcessorResult::EndSessionAndReplyToSender(
        packet,
        "Recovery refused",
    ))
}

/// Client: a recovery this side cannot complete reaches the kernel as a failure, and the session
/// ends.
pub(super) fn fail_client<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    err: NetworkError,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::warn!(target: "citadel", "The recovery could not complete: {err}");
    inner_mut_state!(session.state_container)
        .register_state
        .on_fail();
    session.send_to_kernel(NodeResult::RegisterFailure(RegisterFailure {
        ticket: session.kernel_ticket.get(),
        error_code: Some(err.code_u16()),
        error_message: err.into_string(),
        admission_challenge: None,
    }))?;
    session.shutdown();
    Ok(PrimaryProcessorResult::EndSession(
        "Recovery could not complete",
    ))
}
