//! How a post-quantum login that cannot continue ends: the server answers with a connect FAILURE,
//! the client tells its kernel and ends the session, as a refused login does.

use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::ConnectFail;
use crate::proto::packet_processor::includes::*;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::external_services::ServicesObject;

pub(super) fn failure<R: Ratchet, T: PlatformOps>(
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

/// Client: a sign-in this side cannot complete ends the session, as a refused login does.
pub(super) fn fail_login<R: Ratchet, T: PlatformOps>(
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
    })?;
    Ok(PrimaryProcessorResult::EndSession(
        "Post-quantum sign-in could not complete",
    ))
}
