//! Disconnect Packet Processor for Citadel Protocol
//!
//! This module handles the graceful disconnection process between nodes in the
//! Citadel Protocol network. It implements a two-stage handshake to ensure both
//! parties properly close their connection.
//!
//! # Features
//!
//! - Two-stage disconnect handshake
//! - Secure packet validation
//! - Session state management
//! - Ticket tracking
//! - Kernel notification
//!
//! # Important Notes
//!
//! - Requires connected session state
//! - All packets must be authenticated
//! - Implements brief delay for packet delivery
//! - Manages session state transitions
//! - Notifies kernel of disconnection
//!
//! # Related Components
//!
//! - `StateContainer`: Manages session state
//! - `KernelInterface`: Handles disconnect signals
//! - `SessionManager`: Tracks session lifecycle
//! - `PrimaryStream`: Handles packet transmission

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::packet_processor::primary_group_packet::get_orientation_safe_ratchet;
use citadel_crypt::ratchets::Ratchet;

pub const SUCCESS_DISCONNECT: &str = "Successfully Disconnected";

/// Stage 0: Alice sends Bob a DO_DISCONNECT request packet
/// Stage 1: Bob sends Alice an FINAL, whereafter Alice may disconnect
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_disconnect<R: Ratchet>(
    session: &CitadelSession<R>,
    packet: HdpPacket,
    header_entropy_bank_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if !session.state.is_connected() {
        log::error!(target: "citadel", "disconnect packet received, but session state is not connected. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }

    let hr = {
        let state_container = inner_state!(session.state_container);
        return_if_none!(
            get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
            "Could not get proper HR [disconnect]"
        )
    };

    let (header, payload, _, _) = packet.decompose();
    let (header, _, ratchet) = return_if_none!(
        validation::aead::validate(hr, &header, payload),
        "Unable to validate"
    );
    let ticket = header.context_info.get().into();
    let timestamp = session.time_tracker.get_global_time_ns();
    let security_level = header.security_level.into();

    match header.cmd_aux {
        packet_flags::cmd::aux::do_disconnect::STAGE0 => {
            log::trace!(target: "citadel", "STAGE 0 DISCONNECT PACKET RECEIVED");
            let packet = packet_crafter::do_disconnect::craft_final(
                &ratchet,
                ticket,
                timestamp,
                security_level,
            );
            return_if_none!(
                session.to_primary_stream.as_ref(),
                "Primary stream not loaded"
            )
            .unbounded_send(packet)?;
            // give some time for the outbound task to send the DC message to the adjacent node
            citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(PrimaryProcessorResult::EndSession(SUCCESS_DISCONNECT))
        }

        packet_flags::cmd::aux::do_disconnect::FINAL => {
            trace!(target: "citadel", "STAGE 1 DISCONNECT PACKET RECEIVED (ticket: {ticket})");
            session.kernel_ticket.set(ticket);
            session.state.set(SessionState::Disconnecting);
            log::warn!(target: "citadel", "[DC_SIGNAL:disconnect_packet] Explicit disconnect packet | ticket: {} | cid: {:?}",
                ticket.0, session.session_cid.get());
            session.send_session_dc_signal(Some(ticket), true, SUCCESS_DISCONNECT);
            Ok(PrimaryProcessorResult::EndSession(SUCCESS_DISCONNECT))
        }

        _ => {
            log::error!(target: "citadel", "Invalid aux command on disconnect packet");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
