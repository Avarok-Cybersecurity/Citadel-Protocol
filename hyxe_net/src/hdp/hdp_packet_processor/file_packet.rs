use super::includes::*;
use crate::hdp::hdp_packet_processor::primary_group_packet::get_proper_pqc_and_drill;
use crate::hdp::hdp_server::Ticket;

pub fn process(session: &HdpSession, packet: HdpPacket, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    let session = inner!(session);
    if session.state != SessionState::Connected {
        return PrimaryProcessorResult::Void
    }

    let (header, payload, _, _) = packet.decompose();
    let pqc_sess = session.post_quantum.as_ref()?;
    let cnac_sess = session.cnac.as_ref()?;
    let timestamp = session.time_tracker.get_global_time_ns();
    let mut state_container = inner_mut!(session.state_container);
    // get the proper pqc
    let header_bytes = &header[..];
    let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
    let (pqc, drill) = get_proper_pqc_and_drill(header.drill_version.get(), cnac_sess, pqc_sess, &wrap_inner_mut!(state_container), proxy_cid_info)?;

    // ALL FILE packets must be authenticated
    match validation::group::validate(&drill, &pqc, header_bytes, payload) {
        Some(payload) => {
            match header.cmd_aux {
                packet_flags::cmd::aux::file::FILE_HEADER => {
                    log::info!("RECV FILE HEADER");
                    match validation::file::validate_file_header(&header, &payload[..]) {
                        Some((v_target,vfm)) => {
                            let object_id = vfm.object_id;
                            let ticket = Ticket(header.context_info.get());
                            let security_level = SecurityLevel::for_value(header.security_level as usize)?;
                            let success =  state_container.on_file_header_received(&header, v_target, vfm);
                            let (target_cid, v_target_flipped) = match v_target {
                                VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                    (implicated_cid, VirtualConnectionType::HyperLANPeerToHyperLANPeer(target_cid, implicated_cid))
                                }

                                VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                                    (0, VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid))
                                }

                                _ => {
                                    unimplemented!("HyperWAN functionality not yet enabled")
                                }
                            };

                            let file_header_ack = hdp_packet_crafter::file::craft_file_header_ack_packet(success, object_id, target_cid, &drill, &pqc, ticket, security_level, v_target_flipped, timestamp);
                            PrimaryProcessorResult::ReplyToSender(file_header_ack)
                        }

                        _ => {
                            log::error!("Unable to validate payload of file header");
                            PrimaryProcessorResult::Void
                        }
                    }
                }

                packet_flags::cmd::aux::file::FILE_HEADER_ACK => {
                    log::info!("RECV FILE HEADER ACK");
                    match validation::file::validate_file_header_ack(&header, &payload[..]) {
                        Some((success, object_id, v_target)) => {
                            // the target is the implicated cid of THIS receiving node
                            let implicated_cid = header.target_cid.get();
                            // conclude by passing this data into the state container
                            if let None = state_container.on_file_header_ack_received(success, implicated_cid,header.context_info.get().into(), object_id, v_target) {
                                log::error!("on_file_header_ack_received failed. File transfer attempt invalidated");
                            }
                            PrimaryProcessorResult::Void
                        }

                        _ => {
                            log::error!("Unable to validate FILE HEADER ACK");
                            PrimaryProcessorResult::Void
                        }
                    }
                }

                _ => {
                    log::error!("Invalid FILE auxiliary command received");
                    PrimaryProcessorResult::Void
                }
            }
        }

        _ => {
            log::error!("Unable to AES-GCM validate FILE packet");
            PrimaryProcessorResult::Void
        }
    }
}