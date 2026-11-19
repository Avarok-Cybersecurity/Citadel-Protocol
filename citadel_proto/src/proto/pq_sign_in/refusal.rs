//! How a post-quantum login or registration that cannot continue ends: the server answers with a
//! FAILURE, the client tells its kernel and ends the session, as a refused login does. An
//! admission refusal's public challenge (`AdmissionChallenge`) rides in the FAILURE beside its
//! message, so the client can show the check and try again.

use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::ConnectFail;
use crate::proto::packet_processor::includes::*;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::admission::{challenge_of, AdmissionChallenge};
use citadel_user::external_services::ServicesObject;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};

/// Server: the connect FAILURE for `err`, with its challenge when it carries one.
pub(crate) fn failure<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ratchet: &R,
    err: NetworkError,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> BytesMut {
    let admission_challenge = challenge_of(&err).cloned();
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
        admission_challenge,
        None,
    )
}

/// Client: a sign-in this side cannot complete ends the session, as a refused login does.
pub(crate) fn fail_login<R: Ratchet, T: PlatformOps>(
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
    session.fail_connect(ConnectFail {
        ticket: session.kernel_ticket.get(),
        cid_opt: Some(cid),
        error_message,
        admission_challenge: None,
    })?;
    Ok(PrimaryProcessorResult::EndSession(
        "Post-quantum sign-in could not complete",
    ))
}

/// Leads a registration FAILURE that is a [`RegisterRefusal`] rather than a bare UTF-8 message.
/// No UTF-8 text begins with it, so the two cannot be confused.
const STRUCTURED: u8 = 0xFF;

/// A registration FAILURE that carries a challenge or an error code. Sent only to a client that
/// reads one: an older client takes the whole payload for the message.
#[derive(Serialize, Deserialize)]
struct RegisterRefusal {
    message: String,
    /// A provider this client does not know reads as none: the refusal is still recognised.
    #[serde(default, deserialize_with = "citadel_user::wire_compat::ok_or_default")]
    admission_challenge: Option<AdmissionChallenge>,
    /// The failure's stable error code, for a client at `RECOVERY_SINCE` or later. Appended.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "citadel_negotiation::frame::appended_field"
    )]
    code: Option<u16>,
}

/// What a registration FAILURE told the client.
pub(crate) struct ReadRefusal {
    pub message: String,
    pub admission_challenge: Option<AdmissionChallenge>,
    pub code: Option<u16>,
}

/// Server: the registration FAILURE payload for `err`, for a client that reads a challenge
/// (`reads_challenge`) and an error code (`reads_code`, a client at `RECOVERY_SINCE` or later).
pub(crate) fn register_failure(
    err: NetworkError,
    reads_challenge: bool,
    reads_code: bool,
) -> Vec<u8> {
    let admission_challenge = challenge_of(&err).cloned().filter(|_| reads_challenge);
    let code = Some(err.code_u16()).filter(|_| reads_code);
    let message = err.into_string();
    if admission_challenge.is_none() && code.is_none() {
        return message.into_bytes();
    }
    let refusal = RegisterRefusal {
        message,
        admission_challenge,
        code,
    };
    match refusal.serialize_to_vector() {
        Ok(body) => [&[STRUCTURED][..], &body].concat(),
        Err(err) => {
            log::error!(target: "citadel", "Could not encode a registration refusal: {err}");
            refusal.message.into_bytes()
        }
    }
}

/// Client: what a registration FAILURE payload says, in either form.
pub(crate) fn read_register_failure(payload: Vec<u8>) -> ReadRefusal {
    let plain = |message: String| ReadRefusal {
        message,
        admission_challenge: None,
        code: None,
    };
    match payload.split_first() {
        Some((&STRUCTURED, body)) => match RegisterRefusal::deserialize_from_vector(body) {
            Ok(refusal) => ReadRefusal {
                message: refusal.message,
                admission_challenge: refusal.admission_challenge,
                code: refusal.code,
            },
            Err(_) => plain("Malformed registration refusal".to_string()),
        },
        _ => plain(
            String::from_utf8(payload).unwrap_or_else(|_| "Non-UTF8 error message".to_string()),
        ),
    }
}
