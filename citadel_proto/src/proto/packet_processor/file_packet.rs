use super::includes::*;
use crate::error::NetworkError;
use crate::prelude::{ReVFSResult, Ticket};
use crate::proto::packet_crafter::file::ReVFSPullAckPacket;
use crate::proto::packet_processor::header_to_response_vconn_type;
use crate::proto::packet_processor::primary_group_packet::{
    get_proper_hyper_ratchet, get_resp_target_cid_from_header,
};
use crate::proto::{get_preferred_primary_stream, send_with_error_logging};
use citadel_crypt::misc::TransferType;
use std::sync::atomic::Ordering;

#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "citadel", skip_all, ret, err, fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
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
    let ticket: Ticket = header.context_info.get().into();
    let ts = session.time_tracker.get_global_time_ns();

    // ALL FILE packets must be authenticated
    match validation::group::validate(&hyper_ratchet, security_level, header_bytes, payload) {
        Some(payload) => {
            match header.cmd_aux {
                packet_flags::cmd::aux::file::FILE_HEADER => {
                    log::trace!(target: "citadel", "RECV FILE HEADER");
                    match validation::file::validate_file_header(&header, &payload[..]) {
                        Some(payload) => {
                            let v_target = payload.virtual_target;
                            let vfm = payload.file_metadata;
                            let local_encryption_level = payload.local_encryption_level;
                            log::trace!(target: "citadel", "Declared local encryption level on file header: {local_encryption_level:?}");
                            let (target_cid, v_target_flipped) = match v_target {
                                VirtualConnectionType::LocalGroupPeer(
                                    implicated_cid,
                                    target_cid,
                                ) => (
                                    implicated_cid,
                                    VirtualConnectionType::LocalGroupPeer(
                                        target_cid,
                                        implicated_cid,
                                    ),
                                ),

                                VirtualConnectionType::LocalGroupServer(implicated_cid) => {
                                    (0, VirtualConnectionType::LocalGroupServer(implicated_cid))
                                }

                                _ => {
                                    log::error!(target: "citadel", "HyperWAN functionality not yet enabled");
                                    return Ok(PrimaryProcessorResult::Void);
                                }
                            };

                            let preferred_primary_stream = return_if_none!(
                                get_preferred_primary_stream(&header, session, &state_container)
                            );

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
                                local_encryption_level,
                            ) {
                                log::warn!(target: "citadel", "Failed to run on_file_header_received");
                            }

                            // We do not send a rebound signal until AFTER the local user
                            // accepts the file transfer requests
                            Ok(PrimaryProcessorResult::Void)
                        }

                        _ => {
                            log::error!(target: "citadel", "Unable to validate payload of file header");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::FILE_HEADER_ACK => {
                    log::trace!(target: "citadel", "RECV FILE HEADER ACK");
                    match validation::file::validate_file_header_ack(&header, &payload[..]) {
                        Some(payload) => {
                            let success = payload.success;
                            let object_id = payload.object_id;
                            let v_target = payload.virtual_target;
                            // the target is the implicated cid of THIS receiving node
                            let original_implicated_cid = header.target_cid.get();
                            // conclude by passing this data into the state container
                            if state_container
                                .on_file_header_ack_received(
                                    success,
                                    original_implicated_cid,
                                    header.context_info.get().into(),
                                    object_id,
                                    v_target,
                                )
                                .is_none()
                            {
                                log::error!(target: "citadel", "on_file_header_ack_received failed. File transfer attempt invalidated");
                            }

                            Ok(PrimaryProcessorResult::Void)
                        }

                        _ => {
                            log::error!(target: "citadel", "Unable to validate FILE HEADER ACK");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::REVFS_PULL => {
                    // Let A be the sender, and B be this node, the receiver.
                    // A is asking to pull its own file from B. To do this,
                    // we will send a file_header back to A with auto-accept on.
                    // This will cause the standard file transfer protocol to occur.
                    // The only extra information we need to give the adjacent endpoint
                    // is the metadata pertaining to the encryption strength used on
                    // the data.
                    match validation::file::validate_revfs_pull(&header, &payload) {
                        Some(packet) => {
                            let session = session.clone();
                            let preferred_primary_stream = return_if_none!(
                                get_preferred_primary_stream(&header, &session, &state_container)
                            );
                            let virtual_target = header_to_response_vconn_type(&header);
                            let revfs_cid = header.session_cid.get();
                            let resp_target_cid = get_resp_target_cid_from_header(&header);
                            let delete_on_pull = packet.delete_on_pull;

                            // get the real_path and security level used from the backend
                            let task = async move {
                                let response_payload = match session
                                    .account_manager
                                    .get_persistence_handler()
                                    .revfs_get_file_info(revfs_cid, packet.virtual_path)
                                    .await
                                {
                                    Ok((source, local_encryption_level)) => {
                                        let transfer_type = TransferType::FileTransfer; // use a basic file transfer since we don't need to data to be locally encrypted when sending it back
                                        match session.process_outbound_file(
                                            ticket,
                                            None,
                                            source,
                                            virtual_target,
                                            packet.security_level,
                                            transfer_type,
                                            Some(local_encryption_level),
                                            move |source| {
                                                if delete_on_pull {
                                                    spawn!(tokio::fs::remove_file(source));
                                                }
                                            },
                                        ) {
                                            Ok(_) => ReVFSPullAckPacket::Success,

                                            Err(err) => ReVFSPullAckPacket::Error {
                                                error: err.into_string(),
                                            },
                                        }
                                    }

                                    Err(err) => ReVFSPullAckPacket::Error {
                                        error: err.into_string(),
                                    },
                                };

                                // on top of spawning the file transfer subroutine prior to this,
                                // we will also send a REVFS pull ack
                                let response_packet = packet_crafter::file::craft_revfs_pull_ack(
                                    &hyper_ratchet,
                                    security_level,
                                    ticket,
                                    ts,
                                    resp_target_cid,
                                    response_payload,
                                );
                                send_with_error_logging(&preferred_primary_stream, response_packet);
                            };

                            spawn!(task);

                            Ok(PrimaryProcessorResult::Void)
                        }

                        None => {
                            log::error!(target: "citadel", "Unable to validate REVFS PULL packet");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::REVFS_DELETE => {
                    log::trace!(target: "citadel", "RECV REVFS DELETE");
                    match validation::file::validate_revfs_delete(&header, &payload) {
                        Some(payload) => {
                            let virtual_path = payload.virtual_path;
                            // we use the cid of the sender, because, they are requesting to alter data here
                            let re_vfs_cid = header.session_cid.get();
                            let resp_target_cid = get_resp_target_cid_from_header(&header);
                            let pers = session.account_manager.get_persistence_handler().clone();

                            let preferred_primary_stream = return_if_none!(
                                get_preferred_primary_stream(&header, session, &state_container)
                            );

                            let task = async move {
                                let err_opt = pers
                                    .revfs_delete(re_vfs_cid, virtual_path)
                                    .await
                                    .err()
                                    .map(|e| e.into_string());
                                let response_packet = packet_crafter::file::craft_revfs_ack(
                                    &hyper_ratchet,
                                    security_level,
                                    ticket,
                                    ts,
                                    resp_target_cid,
                                    err_opt,
                                );
                                send_with_error_logging(&preferred_primary_stream, response_packet);
                            };

                            spawn!(task);

                            Ok(PrimaryProcessorResult::Void)
                        }

                        None => {
                            log::error!(target: "citadel", "Unable to validate REVFS DELETE packet");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::REVFS_ACK => {
                    log::trace!(target: "citadel", "RECV REVFS ACK");
                    match validation::file::validate_revfs_ack(&header, &payload) {
                        Some(payload) => {
                            let response = NodeResult::ReVFS(ReVFSResult {
                                error_message: payload.error_msg,
                                data: None,
                                ticket,
                            });

                            session.send_to_kernel(response)?;

                            Ok(PrimaryProcessorResult::Void)
                        }

                        None => {
                            log::error!(target: "citadel", "Unable to validate REVFS ACK packet");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                packet_flags::cmd::aux::file::REVFS_PULL_ACK => {
                    log::trace!(target: "citadel", "RECV REVFS PULL ACK");
                    match validation::file::validate_revfs_pull_ack(&header, &payload) {
                        Some(payload) => match payload {
                            ReVFSPullAckPacket::Success => {
                                // Iwe will not send an ReVFSResult with data quite yet.
                                // Instead, we will send it once the inbound file transfer
                                // is complete
                                Ok(PrimaryProcessorResult::Void)
                            }
                            ReVFSPullAckPacket::Error { error } => {
                                let error_signal = NodeResult::ReVFS(ReVFSResult {
                                    error_message: Some(error),
                                    data: None,
                                    ticket,
                                });

                                session.send_to_kernel(error_signal)?;

                                Ok(PrimaryProcessorResult::Void)
                            }
                        },

                        None => {
                            log::error!(target: "citadel", "Invalid REVFS PULL ACK command received");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                _ => {
                    log::error!(target: "citadel", "Invalid REVFS ACK command received");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        _ => {
            log::error!(target: "citadel", "Unable to AES-GCM validate FILE packet");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
