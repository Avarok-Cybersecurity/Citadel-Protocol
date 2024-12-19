//! File Transfer Packet Processor for Citadel Protocol
//!
//! This module handles secure file transfer operations in the Citadel Protocol network.
//! It manages the entire file transfer lifecycle, including metadata exchange,
//! chunked transfers, error handling, and virtual filesystem operations.
//!
//! # Features
//!
//! - Secure file transfer processing
//! - File metadata handling
//! - Chunked transfer support
//! - Error reporting and recovery
//! - Virtual filesystem integration
//! - Transfer state tracking
//! - Encryption level management
//!
//! # Important Notes
//!
//! - Requires connected session state
//! - All packets must be authenticated
//! - Supports virtual target routing
//! - Handles both direct and proxied transfers
//! - Maintains transfer security levels
//!
//! # Related Components
//!
//! - `StateContainer`: Manages transfer state
//! - `VirtualFileSystem`: Handles file operations
//! - `ObjectTransferHandle`: Tracks transfer progress
//! - `SecurityLevel`: Manages encryption levels
//!
//! # Example Usage
//!
//! ```no_run
//! use citadel_proto::proto::packet_processor::file_packet;
//! use citadel_proto::proto::CitadelSession;
//! use citadel_proto::proto::packet::HdpPacket;
//!
//! fn handle_file_packet(session: &CitadelSession, packet: HdpPacket) {
//!     let proxy_info = None;
//!     match file_packet::process_file_packet(session, packet, proxy_info) {
//!         Ok(result) => {
//!             // Handle successful file operation
//!         }
//!         Err(err) => {
//!             // Handle file operation error
//!         }
//!     }
//! }
//! ```

use super::includes::*;
use crate::error::NetworkError;
use crate::prelude::{InternalServerError, ReVFSResult, Ticket};
use crate::proto::packet_crafter::file::ReVFSPullAckPacket;
use crate::proto::packet_processor::header_to_response_vconn_type;
use crate::proto::packet_processor::primary_group_packet::{
    get_orientation_safe_ratchet, get_resp_target_cid_from_header,
};
use crate::proto::{get_preferred_primary_stream, send_with_error_logging};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::TransferType;

#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub fn process_file_packet<R: Ratchet>(
    session: &CitadelSession<R>,
    packet: HdpPacket,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if !session.state.is_connected() {
        return Ok(PrimaryProcessorResult::Void);
    }

    let (header, payload, _, _) = packet.decompose();

    let mut state_container = inner_mut_state!(session.state_container);
    // get the proper pqc
    let header_bytes = &header[..];
    let header = return_if_none!(Ref::new(header_bytes), "Unable to validate header layout")
        as Ref<&[u8], HdpHeader>;
    let stacked_ratchet = return_if_none!(
        get_orientation_safe_ratchet(
            header.entropy_bank_version.get(),
            &state_container,
            proxy_cid_info
        ),
        "Unable to get proper HR"
    );
    let security_level = header.security_level.into();
    let ticket: Ticket = header.context_info.get().into();
    let ts = session.time_tracker.get_global_time_ns();

    // ALL FILE packets must be authenticated
    match validation::group::validate(&stacked_ratchet, security_level, header_bytes, payload) {
        Some(payload) => {
            match header.cmd_aux {
                packet_flags::cmd::aux::file::FILE_ERROR => {
                    log::error!(target: "citadel", "RECV FILE ERROR");
                    match validation::file::validate_file_error(&header, &payload[..]) {
                        Some(payload) => {
                            let ticket: Ticket = header.context_info.get().into();
                            let target_cid = header.session_cid.get();
                            let object_id = payload.object_id;

                            if let Err(err) = state_container
                                .notify_object_transfer_handle_failure_with(
                                    target_cid,
                                    object_id,
                                    payload.error_message.clone(),
                                )
                            {
                                log::error!(target: "citadel", "Failed to notify object transfer handle failure: {err}");
                            }

                            session.send_to_kernel(NodeResult::InternalServerError(
                                InternalServerError {
                                    ticket_opt: Some(ticket),
                                    message: payload.error_message,
                                    cid_opt: session.session_cid.get(),
                                },
                            ))?;

                            Ok(PrimaryProcessorResult::Void)
                        }

                        _ => {
                            log::error!(target: "citadel", "Unable to validate payload of file error");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }
                packet_flags::cmd::aux::file::FILE_HEADER => {
                    log::trace!(target: "citadel", "RECV FILE HEADER");
                    match validation::file::validate_file_header(&header, &payload[..]) {
                        Some(payload) => {
                            let v_target = payload.virtual_target;
                            let vfm = payload.file_metadata;
                            let local_encryption_level = payload.local_encryption_level;
                            log::trace!(target: "citadel", "Declared local encryption level on file header: {local_encryption_level:?}");
                            let (target_cid, v_target_flipped) = match v_target {
                                VirtualConnectionType::LocalGroupPeer {
                                    session_cid,
                                    peer_cid: target_cid,
                                } => (
                                    session_cid,
                                    VirtualConnectionType::LocalGroupPeer {
                                        session_cid: target_cid,
                                        peer_cid: session_cid,
                                    },
                                ),

                                VirtualConnectionType::LocalGroupServer { session_cid } => {
                                    (0, VirtualConnectionType::LocalGroupServer { session_cid })
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
                                stacked_ratchet,
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
                            let is_p2p =
                                header.session_cid.get() != 0 && header.target_cid.get() != 0;
                            let session_cid = if is_p2p {
                                header.target_cid.get()
                            } else {
                                header.session_cid.get()
                            };
                            //let session_cid = header.session_cid.get();
                            // conclude by passing this data into the state container
                            if state_container
                                .on_file_header_ack_received(
                                    success,
                                    session_cid,
                                    header.context_info.get().into(),
                                    object_id,
                                    v_target,
                                    payload.transfer_type,
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
                                    Ok((source, metadata)) => {
                                        let transfer_type = TransferType::FileTransfer; // use a basic file transfer since we don't need to data to be locally encrypted when sending it back
                                        let Some(local_encryption_level) =
                                            metadata.get_security_level()
                                        else {
                                            log::error!(target: "citadel", "The requested file was not designated as a RE-VFS type, yet, a metadata file existed for it");
                                            return;
                                        };

                                        match session.process_outbound_file(
                                            ticket,
                                            None,
                                            source,
                                            virtual_target,
                                            packet.security_level,
                                            transfer_type,
                                            Some(local_encryption_level),
                                            Some(metadata),
                                            move |source| {
                                                if delete_on_pull {
                                                    spawn!(citadel_io::tokio::fs::remove_file(
                                                        source
                                                    ));
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
                                    &stacked_ratchet,
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
                                    &stacked_ratchet,
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
                                session_cid: stacked_ratchet.get_cid(),
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
                                    session_cid: stacked_ratchet.get_cid(),
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
