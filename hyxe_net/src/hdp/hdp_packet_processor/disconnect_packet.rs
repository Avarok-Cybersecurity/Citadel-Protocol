use super::includes::*;

/// Stage 0: Alice sends Bob a DO_DISCONNECT request packet
/// Stage 1: Bob sends Alice an FINAL, whereafter Alice may disconnect
#[inline]
pub fn process(session: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session);

    if session.state != SessionState::Connected {
        log::error!("disconnect packet received, but session state is not connected. Dropping");
        return PrimaryProcessorResult::Void;
    }


    let cnac = session.cnac.as_ref()?;
    let (header, payload, _, _) = packet.decompose();
    let (header, _, hyper_ratchet) = validation::aead::validate(cnac, &header, payload)?;
    let ticket = header.context_info.get().into();
    let timestamp = session.time_tracker.get_global_time_ns();
    let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_disconnect::STAGE0 => {
                log::info!("STAGE 0 DISCONNECT PACKET RECEIVED");
                let packet = hdp_packet_crafter::do_disconnect::craft_final(&hyper_ratchet, ticket, timestamp, security_level);
                PrimaryProcessorResult::ReplyToSender(packet)
            }

            packet_flags::cmd::aux::do_disconnect::FINAL => {
                log::info!("STAGE 1 DISCONNECT PACKET RECEIVED (ticket: {})", ticket);
                session.kernel_ticket = ticket;
                session.state = SessionState::Disconnected;
                PrimaryProcessorResult::EndSession("Successfully disconnected")
            }

            _ => {
                log::error!("Invalid aux command on disconnect packet");
                PrimaryProcessorResult::Void
            }
        }
}