use super::includes::*;
use crate::error::NetworkError;
use crate::proto::packet_processor::primary_group_packet::get_proper_hyper_ratchet;
use std::sync::atomic::Ordering;

pub const SUCCESS_DISCONNECT: &str = "Successfully Disconnected";

/// Stage 0: Alice sends Bob a DO_DISCONNECT request packet
/// Stage 1: Bob sends Alice an FINAL, whereafter Alice may disconnect
#[cfg_attr(feature = "localhost-testing", tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err, fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub async fn process_disconnect(
    session: &CitadelSession,
    packet: HdpPacket,
    header_drill_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        log::error!(target: "citadel", "disconnect packet received, but session state is not connected. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }

    let hr = {
        let state_container = inner_state!(session.state_container);
        return_if_none!(
            get_proper_hyper_ratchet(header_drill_vers, &state_container, None),
            "Could not get proper HR [disconnect]"
        )
    };

    let (header, payload, _, _) = packet.decompose();
    let (header, _, hyper_ratchet) = return_if_none!(
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
                &hyper_ratchet,
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
            trace!(target: "citadel", "STAGE 1 DISCONNECT PACKET RECEIVED (ticket: {})", ticket);
            session.kernel_ticket.set(ticket);
            session
                .state
                .store(SessionState::Disconnected, Ordering::Relaxed);
            session.send_session_dc_signal(Some(ticket), true, SUCCESS_DISCONNECT);
            Ok(PrimaryProcessorResult::EndSession(SUCCESS_DISCONNECT))
        }

        _ => {
            log::error!(target: "citadel", "Invalid aux command on disconnect packet");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
