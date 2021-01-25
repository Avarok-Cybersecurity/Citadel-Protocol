use super::includes::*;
use crate::hdp::hdp_packet_processor::primary_group_packet::{ToolsetUpdate, get_proper_hyper_ratchet, get_resp_target_cid_from_header, attempt_kem_as_bob, attempt_kem_as_alice_finish};
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;

pub fn process(session: &HdpSession, packet: HdpPacket, header_drill_vers: u32, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    let session = inner!(session);
    if session.state != SessionState::Connected {
        log::error!("Session state is not connected; dropping drill update packet");
        return PrimaryProcessorResult::Void;
    }

    let cnac_sess = session.cnac.as_ref()?;
    let (header, payload, _, _) = packet.decompose();
    let mut state_container = inner_mut!(session.state_container);
    let hyper_ratchet = get_proper_hyper_ratchet(header_drill_vers, cnac_sess, &wrap_inner_mut!(state_container), proxy_cid_info)?;
    let (header, payload) = validation::aead::validate_custom(&hyper_ratchet, &header, payload)?;
    let ref header = header;
    let payload = &payload[..];

    let security_level = header.security_level.into();
    let timestamp = session.time_tracker.get_global_time_ns();

    match header.cmd_aux {
        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE0 => {
            log::info!("DO_DRILL_UPDATE STAGE 0 PACKET RECV");
            match validation::do_drill_update::validate_stage0(payload) {
                Some(transfer) => {
                    let resp_target_cid = get_resp_target_cid_from_header(header);
                    let status = attempt_kem_as_bob(resp_target_cid, header, transfer, &mut state_container.active_virtual_connections, cnac_sess)?;
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

                    let latest_hr = attempt_kem_as_alice_finish(peer_cid, target_cid, transfer.update_status, &mut state_container.active_virtual_connections, Some(constructor), cnac_sess).ok()?.unwrap_or(hyper_ratchet);

                    if let Some(truncate_vers) = needs_truncate {
                        let truncate_packet = hdp_packet_crafter::do_drill_update::craft_truncate(&latest_hr, truncate_vers, resp_target_cid, timestamp, security_level);
                        PrimaryProcessorResult::ReplyToSender(truncate_packet)
                    } else {
                        PrimaryProcessorResult::Void
                    }
                }

                _ => {
                    log::error!("Invalid stage1 DO_DRILL_UPDATE packet");
                    PrimaryProcessorResult::Void
                }
            }
        }

        // Bob will always receive this, whether the toolset being upgraded is a CNAC or a PeerSessionCrypto
        // It is up to Alice to make sure she's removed her hyper ratchet before sending this packet
        packet_flags::cmd::aux::do_drill_update::TRUNCATE => {
            log::info!("DO_DRILL_UPDATE TRUNCATE PACKET RECV");
            let truncate_packet = validation::do_drill_update::validate_truncate(payload)?;
            let resp_target_cid = get_resp_target_cid_from_header(header);

            let mut method = if resp_target_cid != ENDPOINT_ENCRYPTION_OFF {
                let crypt = &mut state_container.active_virtual_connections.get_mut(&resp_target_cid)?.endpoint_container.as_mut()?.endpoint_crypto;
                let local_cid = header.target_cid.get();
                ToolsetUpdate::E2E { crypt, local_cid }
            } else {
                // Cnac
                ToolsetUpdate::SessCNAC(cnac_sess)
            };

            match method.deregister(truncate_packet.truncate_version) {
                Ok(_) => {
                    log::info!("[Toolset Update] Successfully truncated version {}", truncate_packet.truncate_version)
                },
                Err(err) => {
                    log::error!("[Toolset Update] Error truncating vers {}: {:?}", truncate_packet.truncate_version, err);
                }
            }

            PrimaryProcessorResult::Void
        }

        _ => {
            log::error!("Invalid auxilliary command for DO_DRILL_UPDATE packet. Dropping");
            PrimaryProcessorResult::Void
        }
    }
}