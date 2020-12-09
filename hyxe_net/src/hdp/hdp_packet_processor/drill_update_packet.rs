use super::includes::*;

pub fn process(session: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = inner!(session);
    if session.state != SessionState::Connected {
        log::error!("Session state is not connected; dropping drill update packet");
        return PrimaryProcessorResult::Void;
    }

    let pqc = session.post_quantum.as_ref()?;
    let cnac = session.cnac.as_ref()?;
    let (header, payload, _, _) = packet.decompose();
    let (header, payload, drill) = validation::aead::validate(cnac, pqc, &header, payload)?;
    let ref header = header;
    let payload = &payload[..];

    let timestamp = session.time_tracker.get_global_time_ns();
    let mut state_container = inner_mut!(session.state_container);
    match header.cmd_aux {
        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE0 => {
            log::info!("DO_DRILL_UPDATE STAGE 0 PACKET RECV");
            // The receiving node of a stage 0 packet should not initially have in-progress set as true
            if !state_container.drill_update_state.in_progress {
                state_container.drill_update_state.in_progress = true;
                state_container.drill_update_state.last_stage = packet_flags::cmd::aux::do_drill_update::STAGE1;
                let nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = drill.get_random_aes_gcm_nonce();

                let stage1_packet = hdp_packet_crafter::do_drill_update::craft_stage1(&drill, pqc, &nonce, timestamp);
                state_container.drill_update_state.nonce = Some(nonce);
                state_container.drill_update_state.on_packet_received(timestamp);

                PrimaryProcessorResult::ReplyToSender(stage1_packet)
            } else {
                log::error!("Drill update state in progress; dropping stage zero packet");
                PrimaryProcessorResult::Void
            }
        }


        // Alice
        packet_flags::cmd::aux::do_drill_update::STAGE1 => {
            log::info!("DO_DRILL_UPDATE STAGE 1 PACKET RECV");
            if state_container.drill_update_state.in_progress && state_container.drill_update_state.last_stage == packet_flags::cmd::aux::do_drill_update::STAGE0 {
                if let Some(nonce) = validation::do_drill_update::validate_stage1(payload) {
                    if let Ok((drill_update_object, proposed_new_drill)) = cnac.generate_new_dou(&drill) {
                        if let Some(stage2_packet) = hdp_packet_crafter::do_drill_update::craft_stage2(&drill, drill_update_object, pqc, &nonce, timestamp) {
                            state_container.drill_update_state.nonce = Some(nonce);
                            state_container.drill_update_state.last_stage = packet_flags::cmd::aux::do_drill_update::STAGE1;
                            // We do not commit the new Drill into the toolset quite yet. Instead, store it
                            state_container.drill_update_state.new_drill = Some(proposed_new_drill);
                            state_container.drill_update_state.on_packet_received(timestamp);

                            PrimaryProcessorResult::ReplyToSender(stage2_packet)
                        } else {
                            log::error!("Unable to create stage 1 packet. Ending session for security purposes");
                            PrimaryProcessorResult::EndSession("Unable to update drill")
                        }
                    } else {
                        log::error!("Unable to validate stage 1 packet");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Unable to validate stage 1 packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Invalid state on node for a stage 1 packet to commence. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE2 => {
            log::info!("DO_DRILL_UPDATE STAGE 2 PACKET RECV");
            if state_container.drill_update_state.in_progress && state_container.drill_update_state.last_stage == packet_flags::cmd::aux::do_drill_update::STAGE1 {
                let nonce = state_container.drill_update_state.nonce.as_ref()?;

                if let Some(next_drill) = validation::do_drill_update::validate_stage2(&drill, pqc, nonce, payload) {
                    // While we have the next drill, we can't register it to the toolbox yet. We need to validate it by sending a stage 3 packet
                    let stage3_packet = hdp_packet_crafter::do_drill_update::craft_stage3(&drill, &next_drill, nonce, pqc, timestamp);
                    state_container.drill_update_state.new_drill = Some(next_drill);
                    state_container.drill_update_state.last_stage = packet_flags::cmd::aux::do_drill_update::STAGE2;
                    state_container.drill_update_state.on_packet_received(timestamp);

                    PrimaryProcessorResult::ReplyToSender(stage3_packet)
                } else {
                    log::error!("Unable to validate stage 2 packet");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Invalid state on node for a stage 2 packet to commence. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_drill_update::STAGE3 => {
            log::info!("DO_DRILL_UPDATE STAGE 3 PACKET RECV");
            if state_container.drill_update_state.in_progress && state_container.drill_update_state.last_stage == packet_flags::cmd::aux::do_drill_update::STAGE1 {
                let new_drill = state_container.drill_update_state.new_drill.as_ref()?;
                let expected_nonce = state_container.drill_update_state.nonce.as_ref()?;

                if validation::do_drill_update::validate_stage3(new_drill, pqc, expected_nonce, payload) {
                    // register the drill, send a success packet
                    if cnac.register_new_drill_to_toolset(new_drill.clone()) {
                        // we cannot use the new drill yet to encrypt the packet, because the other end has not yet registered it
                        let success_packet = hdp_packet_crafter::do_drill_update::craft_final(&drill, pqc, true, timestamp);
                        state_container.drill_update_state.on_packet_received(timestamp);
                        state_container.drill_update_state.on_success();
                        //log::info!("Success registering new drill to toolset. Sending SUCCESS packet");
                        PrimaryProcessorResult::ReplyToSender(success_packet)
                    } else {
                        log::error!("Unable to register drill. Ending session for security purposes");
                        PrimaryProcessorResult::EndSession("Unable to update drill")
                    }
                } else {
                    log::error!("Unable to validate stage 3 packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("The packet is a stage 3 packet, but the internal state is not 1. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_drill_update::SUCCESS => {
            log::info!("DO_DRILL_UPDATE STAGE SUCCESS PACKET RECV");
            if state_container.drill_update_state.in_progress && state_container.drill_update_state.last_stage == packet_flags::cmd::aux::do_drill_update::STAGE2 {
                let new_drill = state_container.drill_update_state.new_drill.as_ref()?;
                if cnac.register_new_drill_to_toolset(new_drill.clone()) {
                    //log::info!("Success registering new drill to toolset. Drill update subroutine finished!");
                    state_container.drill_update_state.on_packet_received(timestamp);
                    state_container.drill_update_state.on_success();
                    PrimaryProcessorResult::Void
                } else {
                    log::error!("Unable to register new drill to toolset");
                    state_container.drill_update_state.on_fail();
                    PrimaryProcessorResult::EndSession("Unable to update drill")
                }
            } else {
                log::error!("The packet is a stage success packet, but the internal state is not 2. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_drill_update::FAILURE => {
            log::info!("DO_DRILL_UPDATE STAGE FAILURE PACKET RECV");
            if state_container.drill_update_state.in_progress && state_container.drill_update_state.last_stage == packet_flags::cmd::aux::do_drill_update::STAGE2 {
                log::error!("Drill validation has failed. Ending session for security purposes");
                // TODO: Drill rollback mechanism?
                PrimaryProcessorResult::EndSession("Unable to update drill")
            } else {
                log::error!("The packet is a stage failure packet, but the internal state is not 2. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        _ => {
            log::error!("Invalid auxilliary command for DO_DRILL_UPDATE packet. Dropping");
            PrimaryProcessorResult::Void
        }
    }
}