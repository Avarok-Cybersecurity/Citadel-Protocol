use super::includes::*;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;

pub fn process(session: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = inner!(session);
    if session.state != SessionState::Connected {
        log::error!("Session state is not connected; dropping drill update packet");
        return PrimaryProcessorResult::Void;
    }

    let cnac = session.cnac.as_ref()?;
    let (header, payload, _, _) = packet.decompose();
    let (header, payload, hyper_ratchet) = validation::aead::validate(cnac, &header, payload)?;
    let ref header = header;
    let payload = &payload[..];

    let timestamp = session.time_tracker.get_global_time_ns();

    match header.cmd_aux {
        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE0 => {
            log::info!("DO_DRILL_UPDATE STAGE 0 PACKET RECV");
            match validation::do_drill_update::validate_stage0(payload) {
                Some(transfer) => {
                    let algorithm = header.algorithm;
                    let new_drill_version = header.drill_version.get().wrapping_add(1);
                    let cid = header.session_cid.get();

                    let bob_constructor = HyperRatchetConstructor::new_bob(algorithm, cid, new_drill_version, transfer)?;
                    let transfer = bob_constructor.stage0_bob()?;
                    let new_hyper_ratchet = bob_constructor.finish()?;
                    log::info!("[BOB] success creating HyperRatchet v {}", new_hyper_ratchet.version());
                    cnac.register_new_hyper_ratchet(new_hyper_ratchet.clone()).ok()?;
                    let packet = hdp_packet_crafter::do_drill_update::craft_stage1(&hyper_ratchet, transfer, timestamp);
                    PrimaryProcessorResult::ReplyToSender(packet)
                }

                _ => {
                    log::error!("Invalid stage0 DO_DRILL_UPDATE packet");
                    PrimaryProcessorResult::Void
                }
            }
        }


        // Alice
        packet_flags::cmd::aux::do_drill_update::STAGE1 => {
            log::info!("DO_DRILL_UPDATE STAGE 1 PACKET RECV");
            match validation::do_drill_update::validate_stage1(payload) {
                Some(transfer) => {
                    let mut state_container = inner_mut!(session.state_container);
                    let mut hyper_ratchet = state_container.drill_update_state.alice_hyper_ratchet.take()?;
                    hyper_ratchet.stage1_alice(transfer)?;
                    let new_hyper_ratchet = hyper_ratchet.finish()?;
                    let vers = new_hyper_ratchet.version();
                    cnac.register_new_hyper_ratchet(new_hyper_ratchet).ok()?;
                    log::info!("[ALICE] success registering HyperRatchet v {}", vers);

                    PrimaryProcessorResult::Void
                }

                _ => {
                    log::error!("Invalid stage1 DO_DRILL_UPDATE packet");
                    PrimaryProcessorResult::Void
                }
            }
        }

        _ => {
            log::error!("Invalid auxilliary command for DO_DRILL_UPDATE packet. Dropping");
            PrimaryProcessorResult::Void
        }
    }
}