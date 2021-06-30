use super::includes::*;
use crate::hdp::hdp_packet_processor::primary_group_packet::{ToolsetUpdate, get_proper_hyper_ratchet, get_resp_target_cid_from_header, attempt_kem_as_bob, attempt_kem_as_alice_finish};
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransferType, ConstructorType};
use hyxe_crypt::hyper_ratchet::RatchetType;
use crate::hdp::hdp_server::SecrecyMode;
use std::ops::Deref;

pub fn process(session: &HdpSession, packet: HdpPacket, header_drill_vers: u32, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    if session.state.get() != SessionState::Connected {
        log::error!("Session state is not connected; dropping drill update packet");
        return PrimaryProcessorResult::Void;
    }

    let HdpSessionInner {
        cnac,
        state_container,
        time_tracker,
        security_settings,
        ..
    } = session.inner.deref();

    let ref cnac_sess = cnac.get()?;
    let (header, payload, _, _) = packet.decompose();
    let mut state_container = inner_mut!(state_container);

    let hyper_ratchet = get_proper_hyper_ratchet(header_drill_vers, cnac_sess, &wrap_inner_mut!(state_container), proxy_cid_info)?;
    let (header, payload) = validation::aead::validate_custom(&hyper_ratchet, &header, payload)?;
    let ref header = header;
    let payload = &payload[..];

    let security_level = header.security_level.into();
    let timestamp = time_tracker.get_global_time_ns();

    match header.cmd_aux {
        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE0 => {
            log::info!("DO_DRILL_UPDATE STAGE 0 PACKET RECV");
            match validation::do_drill_update::validate_stage0(payload) {
                Some(transfer) => {
                    let resp_target_cid = get_resp_target_cid_from_header(header);
                    let status = attempt_kem_as_bob(resp_target_cid, header, Some(AliceToBobTransferType::Default(transfer)), &mut state_container.active_virtual_connections, cnac_sess)?;
                    let packet = hdp_packet_crafter::do_drill_update::craft_stage1(&hyper_ratchet,status, timestamp, resp_target_cid, security_level);
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
                    //let mut state_container = inner_mut!(session.state_container);
                    let peer_cid = header.session_cid.get();
                    let target_cid = header.target_cid.get();
                    let resp_target_cid = get_resp_target_cid_from_header(header);
                    let needs_truncate = transfer.update_status.requires_truncation();
                    let constructor = if target_cid != ENDPOINT_ENCRYPTION_OFF { state_container.drill_update_state.p2p_updates.remove(&peer_cid)? } else { state_container.drill_update_state.alice_hyper_ratchet.take()? };
                    log::info!("Obtained constructor for {}", resp_target_cid);
                    let secrecy_mode = security_settings.get().map(|r| r.secrecy_mode).clone()?;

                    let latest_hr = attempt_kem_as_alice_finish(secrecy_mode, peer_cid, target_cid, transfer.update_status, &mut state_container.active_virtual_connections, Some(ConstructorType::Default(constructor)), cnac_sess).ok()?.unwrap_or(RatchetType::Default(hyper_ratchet)).assume_default()?;
                    let truncate_packet = hdp_packet_crafter::do_drill_update::craft_truncate(&latest_hr, needs_truncate, resp_target_cid, timestamp, security_level);
                    PrimaryProcessorResult::ReplyToSender(truncate_packet)
                }

                _ => {
                    log::error!("Invalid stage1 DO_DRILL_UPDATE packet");
                    PrimaryProcessorResult::Void
                }
            }
        }

        // Bob will always receive this, whether the toolset being upgraded or not. This allows Bob to begin using the latest drill version
        packet_flags::cmd::aux::do_drill_update::TRUNCATE => {
            log::info!("DO_DRILL_UPDATE TRUNCATE PACKET RECV");
            let truncate_packet = validation::do_drill_update::validate_truncate(payload)?;
            let resp_target_cid = get_resp_target_cid_from_header(header);

            let (mut method, secrecy_mode) = if resp_target_cid != ENDPOINT_ENCRYPTION_OFF {
                let endpoint_container = state_container.active_virtual_connections.get_mut(&resp_target_cid)?.endpoint_container.as_mut()?;
                let crypt = &mut endpoint_container.endpoint_crypto;
                let local_cid = header.target_cid.get();
                (ToolsetUpdate::E2E { crypt, local_cid }, endpoint_container.default_security_settings.secrecy_mode)
            } else {
                // Cnac
                (ToolsetUpdate::SessCNAC(cnac_sess), security_settings.get().map(|r| r.secrecy_mode).clone().unwrap())
            };

            // We optionally deregister at this endpoint to prevent any further packets with this version from being sent
            if let Some(truncate_vers) = truncate_packet.truncate_version {
                match method.deregister(truncate_vers) {
                    Ok(_) => {
                        log::info!("[Toolset Update] Successfully truncated version {}", truncate_vers)
                    },
                    Err(err) => {
                        log::error!("[Toolset Update] Error truncating vers {}: {:?}", truncate_vers, err);
                    }
                }
            }

            // We update the internal latest version usable
            method.post_stage1_alice_or_bob();

            let lock_set_by_alice = method.unlock(false)?.1;

            // if lock set by bob, do poll
            let do_poll = lock_set_by_alice.map(|r| !r).unwrap_or(false);

            std::mem::drop(state_container);


            // If we didn't have to deregister, then our job is done. alice does not need to hear from Bob
            // But, if deregistration occured, we need to alert alice that way she can unlock hers
            if let Some(truncate_vers) = truncate_packet.truncate_version {
                let truncate_ack = hdp_packet_crafter::do_drill_update::craft_truncate_ack(&hyper_ratchet, truncate_vers, resp_target_cid, timestamp, security_level);
                session.send_to_primary_stream(None, truncate_ack)?;
            }

            if secrecy_mode == SecrecyMode::Perfect {
                if do_poll {
                    let _ = session.poll_next_enqueued(resp_target_cid)?;
                }
            }

            PrimaryProcessorResult::Void
        }

        packet_flags::cmd::aux::do_drill_update::TRUNCATE_ACK => {
            log::info!("DO_DRILL_UPDATE TRUNCATE_ACK PACKET RECV");
            let truncate_ack_packet = validation::do_drill_update::validate_truncate_ack(payload)?;
            log::info!("Adjacent node has finished deregistering version {}", truncate_ack_packet.truncated_version);

            let resp_target_cid = get_resp_target_cid_from_header(header);

            let (mut method, secrecy_mode) = if resp_target_cid != ENDPOINT_ENCRYPTION_OFF {
                let endpoint_container = state_container.active_virtual_connections.get_mut(&resp_target_cid)?.endpoint_container.as_mut()?;
                let crypt = &mut endpoint_container.endpoint_crypto;
                let local_cid = header.target_cid.get();
                (ToolsetUpdate::E2E { crypt, local_cid }, endpoint_container.default_security_settings.secrecy_mode)
            } else {
                // Cnac
                (ToolsetUpdate::SessCNAC(cnac_sess), security_settings.get().map(|r| r.secrecy_mode).clone().unwrap())
            };

            let _ = method.unlock(false)?; // unconditional unlock

            // now, we can poll any packets
            std::mem::drop(state_container);
            if secrecy_mode == SecrecyMode::Perfect {
                let _ = session.poll_next_enqueued(resp_target_cid)?;
            }

            PrimaryProcessorResult::Void
        }

        _ => {
            log::error!("Invalid auxiliary command for DO_DRILL_UPDATE packet. Dropping");
            PrimaryProcessorResult::Void
        }
    }
}