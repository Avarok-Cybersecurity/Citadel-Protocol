use super::includes::*;
use crate::error::NetworkError;
use std::sync::atomic::Ordering;

/// Stage 0: Alice sends Bob a DO_DISCONNECT request packet
/// Stage 1: Bob sends Alice an FINAL, whereafter Alice may disconnect
#[inline]
pub fn process(session: &HdpSession, packet: HdpPacket) -> Result<PrimaryProcessorResult, NetworkError> {
    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        log::error!("disconnect packet received, but session state is not connected. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }


    let ref cnac = return_if_none!(inner_state!(session.state_container).cnac.clone(), "Sess CNAC not loaded");
    let (header, payload, _, _) = packet.decompose();
    let (header, _, hyper_ratchet) = return_if_none!(validation::aead::validate(cnac, &header, payload), "Unable to validate");
    let ticket = header.context_info.get().into();
    let timestamp = session.time_tracker.get_global_time_ns();
    let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_disconnect::STAGE0 => {
                log::info!("STAGE 0 DISCONNECT PACKET RECEIVED");
                let packet = hdp_packet_crafter::do_disconnect::craft_final(&hyper_ratchet, ticket, timestamp, security_level);
                return_if_none!(session.to_primary_stream.as_ref(), "Primary stream not loaded").unbounded_send(packet)?;
                Ok(PrimaryProcessorResult::EndSession("Successfully disconnected"))
            }

            packet_flags::cmd::aux::do_disconnect::FINAL => {
                log::info!("STAGE 1 DISCONNECT PACKET RECEIVED (ticket: {})", ticket);
                session.kernel_ticket.set(ticket);
                session.state.store(SessionState::Disconnected, Ordering::Relaxed);
                Ok(PrimaryProcessorResult::EndSession("Successfully disconnected"))
            }

            _ => {
                log::error!("Invalid aux command on disconnect packet");
                Ok(PrimaryProcessorResult::Void)
            }
        }
}