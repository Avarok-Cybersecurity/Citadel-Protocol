use super::includes::*;
use crate::error::NetworkError;
use crate::hdp::packet_processor::primary_group_packet::get_proper_hyper_ratchet;
use std::sync::atomic::Ordering;

#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "lusna", skip_all, ret, err, fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub fn process_file_packet(
    session: &HdpSession,
    packet: HdpPacket,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        return Ok(PrimaryProcessorResult::Void);
    }

    let (header, payload, _, _) = packet.decompose();

    let mut state_container = inner_mut_state!(session.state_container);
    // get the proper pqc
    let header_bytes = &header[..];
    let header = return_if_none!(
        LayoutVerified::new(header_bytes),
        "Unable to validate header layout"
    ) as LayoutVerified<&[u8], HdpHeader>;
    let hyper_ratchet = return_if_none!(
        get_proper_hyper_ratchet(header.drill_version.get(), &state_container, proxy_cid_info),
        "Unable to get proper HR"
    );
    let security_level = header.security_level.into();
    // ALL FILE packets must be authenticated
    match validation::group::validate(&hyper_ratchet, security_level, header_bytes, payload) {
        Some(payload) => {
            match header.cmd_aux {
                packet_flags::cmd::aux::file::FILE_HEADER => {
                    log::trace!(target: "lusna", "RECV FILE HEADER");
                    match validation::file::validate_file_header(&header, &payload[..]) {
                        Some((v_target, vfm)) => {
                            let (target_cid, v_target_flipped) = match v_target {
                                VirtualConnectionType::HyperLANPeerToHyperLANPeer(
                                    implicated_cid,
                                    target_cid,
                                ) => (
                                    implicated_cid,
                                    VirtualConnectionType::HyperLANPeerToHyperLANPeer(
                                        target_cid,
                                        implicated_cid,
                                    ),
                                ),

                                VirtualConnectionType::HyperLANPeerToHyperLANServer(
                                    implicated_cid,
                                ) => (
                                    0,
                                    VirtualConnectionType::HyperLANPeerToHyperLANServer(
                                        implicated_cid,
                                    ),
                                ),

                                _ => {
                                    log::error!(target: "lusna", "HyperWAN functionality not yet enabled");
                                    return Ok(PrimaryProcessorResult::Void);
                                }
                            };

                            let preferred_primary_stream = if header.target_cid.get() != 0 {
                                state_container
                                    .get_preferred_stream(header.session_cid.get())
                                    .clone()
                            } else {
                                return_if_none!(session.to_primary_stream.clone())
                            };

                            if !state_container.on_file_header_received(
                                &header,
                                v_target,
                                vfm,
                                session.account_manager.get_persistence_handler(),
                                session.state_container.clone(),
                                hyper_ratchet,
                                target_cid,
                                v_target_flipped,
                                preferred_primary_stream,
                            ) {
                                log::warn!(target: "lusna", "Failed to run on_file_header_received");
                            }

                            // We do not send a rebound signal until AFTER the local user
                            // accepts the file transfer requests
                            Ok(PrimaryProcessorResult::Void)
                        }

                        _ => {
                            log::error!(target: "lusna", "Unable to validate payload of file header");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::FILE_HEADER_ACK => {
                    log::trace!(target: "lusna", "RECV FILE HEADER ACK");
                    match validation::file::validate_file_header_ack(&header, &payload[..]) {
                        Some((success, object_id, v_target)) => {
                            // the target is the implicated cid of THIS receiving node
                            let implicated_cid = header.target_cid.get();
                            // conclude by passing this data into the state container
                            if let None = state_container.on_file_header_ack_received(
                                success,
                                implicated_cid,
                                header.context_info.get().into(),
                                object_id,
                                v_target,
                            ) {
                                log::error!(target: "lusna", "on_file_header_ack_received failed. File transfer attempt invalidated");
                            }

                            Ok(PrimaryProcessorResult::Void)
                        }

                        _ => {
                            log::error!(target: "lusna", "Unable to validate FILE HEADER ACK");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                _ => {
                    log::error!(target: "lusna", "Invalid FILE auxiliary command received");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        _ => {
            log::error!(target: "lusna", "Unable to AES-GCM validate FILE packet");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
