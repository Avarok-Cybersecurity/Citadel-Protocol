//! Primary Group Packet Processor for Citadel Protocol
//!
//! This module handles the processing of group packets in the Citadel Protocol network.
//! It manages secure group communication, including message distribution, file transfers,
//! and cryptographic operations for group sessions.
//!
//! # Features
//!
//! - Group packet validation and processing
//! - Secure message distribution
//! - File transfer management
//! - Group session cryptography
//! - Proxy packet handling
//! - UDP and TCP transport support
//! - KEM (Key Encapsulation Mechanism) operations
//!
//! # Important Notes
//!
//! - Group packets require an established session
//! - Supports both direct and proxied communication
//! - Handles TCP-only mode for group payloads
//! - Implements automatic group expiry
//! - Manages cryptographic state for group sessions
//!
//! # Related Components
//!
//! - `StateContainer`: Manages group session state
//! - `StackedRatchet`: Provides cryptographic primitives
//! - `PeerSessionCrypto`: Handles peer-to-peer encryption
//! - `VirtualConnection`: Manages group connections

use super::includes::*;
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::error::NetworkError;
use crate::functional::IfTrueConditional;
use crate::inner_arg::ExpectedInnerTarget;
use crate::prelude::InternalServerError;
use crate::proto::node_result::OutboundRequestRejected;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::session_queue_handler::QueueWorkerResult;
use crate::proto::state_container::{FileKey, GroupKey, StateContainerInner};
use crate::proto::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::prelude::ObjectId;
use citadel_types::proto::UdpMode;
use std::ops::Deref;

/// This will handle an inbound primary group packet
/// NOTE: Since incorporating the proxy features, if a packet gets to this process closure, it implies the packet
/// has reached its destination. Just need to ensure that intermediary packets get the proper target_cid on the headers that way
/// they proxy
/// `proxy_cid_info`: is None if the packets were not proxied, and will thus use the session's pqcrypto to authenticate the data.
/// If `proxy_cid_info` is Some, then a tuple of the original implicated cid (peer cid) and the original target cid (this cid)
/// will be provided. In this case, we must use the virtual conn's crypto
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub fn process_primary_packet<R: Ratchet>(
    session_ref: &CitadelSession<R>,
    cmd_aux: u8,
    packet: HdpPacket,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;

    let CitadelSessionInner {
        time_tracker,
        state_container,
        state,
        ..
    } = session.inner.deref();

    if !state.is_connected() {
        log::warn!(target: "citadel", "Group packet dropped; session not connected");
        return Ok(PrimaryProcessorResult::Void);
    }

    // Group payloads are not validated in the same way the primary packets are (with the exception of FAST_MSG's in GROUP_HEADERS)
    // While group payloads are typically processed by the wave ports, it is possible
    // that TCP_ONLY mode is engaged, in which case, the packets are funneled through here
    let (header, payload, _, _) = packet.decompose();

    let timestamp = time_tracker.get_global_time_ns();

    let mut state_container = inner_mut_state!(state_container);
    let udp_mode = state_container.udp_mode;
    // get the proper pqc
    let header_bytes = &header[..];
    let header = return_if_none!(Ref::new(header_bytes), "Unable to load header [PGP]")
        as Ref<&[u8], HdpHeader>;
    let ratchet = return_if_none!(
        get_orientation_safe_ratchet(
            header.entropy_bank_version.get(),
            &state_container,
            proxy_cid_info
        ),
        "Unable to get proper StackedRatchet [PGP]"
    );
    let security_level = header.security_level.into();
    //log::trace!(target: "citadel", "[Peer StackedRatchet] Obtained version {} w/ CID {} (local CID: {})", ratchet.version(), ratchet.get_cid(), header.session_cid.get());
    match header.cmd_aux {
        packet_flags::cmd::aux::group::GROUP_PAYLOAD => {
            log::trace!(target: "citadel", "RECV GROUP PAYLOAD {header:?}");
            // These packets do not get encrypted with the message key. They get scrambled and encrypted
            match state_container.on_group_payload_received(&header, payload.freeze(), &ratchet) {
                Ok(res) => {
                    state_container.meta_expiry_state.on_event_confirmation();
                    Ok(res)
                }

                Err((err, ticket, object_id)) => {
                    log::error!(target: "citadel", "on_group_payload_received error: {err:?}");
                    // Send an error packet back to the source and send a signal to the handle
                    // TODO: File transfer handle cleanup on failure
                    if let Err(err) = state_container.notify_object_transfer_handle_failure(
                        &header,
                        err.to_string(),
                        object_id,
                    ) {
                        log::error!(target: "citadel", "Unable to notify object transfer handle failure: {err:?}");
                        // Send error to kernel instead
                        session.send_to_kernel(NodeResult::InternalServerError(
                            InternalServerError {
                                ticket_opt: Some(ticket),
                                message: err.to_string(),
                                cid_opt: session.session_cid.get(),
                            },
                        ))?;
                    }

                    let v_conn = get_v_conn_from_header(&header);

                    // Finally, alert the adjacent endpoint by crafting an error packet
                    let error_packet = packet_crafter::file::craft_file_error_packet(
                        &ratchet,
                        ticket,
                        security_level,
                        v_conn,
                        timestamp,
                        err.into_string(),
                        object_id,
                    );
                    Ok(PrimaryProcessorResult::ReplyToSender(error_packet))
                }
            }
        }

        _ => {
            match validation::aead::validate_custom(&ratchet, &*header, payload) {
                Some((header, payload)) => {
                    state_container.meta_expiry_state.on_event_confirmation();
                    match cmd_aux {
                        packet_flags::cmd::aux::group::GROUP_HEADER => {
                            log::trace!(target: "citadel", "RECV GROUP HEADER");
                            let group_header = return_if_none!(
                                validation::group::validate_header(&payload),
                                "Bad non-message group header"
                            );

                            match group_header {
                                GroupHeader::Ratchet(ratchet_message, object_id) => {
                                    log::trace!(target: "citadel", "Recv FastMessage. version {} w/ CID {} (local CID: {})", ratchet.version(), ratchet.get_cid(), header.session_cid.get());
                                    // Here, we do not go through all the fiasco like above. We just forward the message to the kernel, then send an ACK
                                    // so that the sending side can be notified of a successful send
                                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                                    log::trace!(target: "citadel", "Resp target cid {} obtained. version {} w/ CID {} (local CID: {})", resp_target_cid, ratchet.version(), ratchet.get_cid(), header.session_cid.get());
                                    let ticket = header.context_info.get().into();
                                    // we call this to ensure a flood of these packets doesn't cause ordinary groups from being dropped
                                    // let v_conn = get_v_conn_from_header(&header);
                                    let target_cid =
                                        if let Some((original_session_cid, _original_target_cid)) =
                                            proxy_cid_info
                                        {
                                            original_session_cid
                                        } else {
                                            0
                                        };

                                    if let Err(err) = state_container
                                        .forward_data_to_ordered_channel(
                                            target_cid,
                                            header.group.get(),
                                            ratchet_message,
                                        )
                                    {
                                        log::error!(target: "citadel", "Unable to forward data to channel (peer: {target_cid}): {err:?}");
                                        return Ok(PrimaryProcessorResult::Void);
                                    }

                                    let group_header_ack =
                                        packet_crafter::group::craft_group_header_ack(
                                            &ratchet,
                                            header.group.get(),
                                            resp_target_cid,
                                            object_id,
                                            ticket,
                                            None,
                                            true,
                                            timestamp,
                                            security_level,
                                        );

                                    Ok(PrimaryProcessorResult::ReplyToSender(group_header_ack))
                                }

                                GroupHeader::Standard(group_receiver_config, virtual_target) => {
                                    // First, check to make sure the virtual target can accept
                                    let object_id = group_receiver_config.object_id;
                                    let ticket = header.context_info.get().into();

                                    //let sess_session_cid = session.session_cid.load(Ordering::Relaxed)?;
                                    //let target_cid_header = header.target_cid.get();
                                    // for HyperLAN conns, this is true

                                    let resp_target_cid = return_if_none!(
                                        get_resp_target_cid(&virtual_target),
                                        "Unable to get resp_target_cid [PGP]"
                                    );

                                    // the below will return None if not ready to accept
                                    let initial_wave_window = state_container
                                        .on_group_header_received(
                                            &header,
                                            group_receiver_config,
                                            virtual_target,
                                        );
                                    if initial_wave_window.is_some() {
                                        // register group timeout device
                                        //std::mem::drop(state_container);
                                        let group_id = header.group.get();
                                        let peer_cid = header.session_cid.get();

                                        session.queue_handle.insert_ordinary(group_id as usize, peer_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                                            let key = GroupKey::new(peer_cid, group_id, object_id);
                                            if let Some(group) = state_container.inbound_groups.get(&key) {
                                                if group.has_begun {
                                                    if group.receiver.has_expired(GROUP_EXPIRE_TIME_MS) {
                                                        if state_container.meta_expiry_state.expired() {
                                                            log::warn!(target: "citadel", "Inbound group {group_id} has expired; removing for {peer_cid}.");
                                                            if let Some(group) = state_container.inbound_groups.remove(&key) {
                                                                if group.object_id != ObjectId::zero() {
                                                                    // belongs to a file. Delete file; stop transmission
                                                                    let key = FileKey::new(group.object_id);
                                                                    if let Some(_file) = state_container.inbound_files.remove(&key) {
                                                                        // dropping this will automatically drop the future streaming to HD
                                                                        log::warn!(target: "citadel", "File transfer expired");
                                                                        // TODO: Create file FIN
                                                                    }

                                                                    let _ = state_container.file_transfer_handles.remove(&key);
                                                                }
                                                            }

                                                            QueueWorkerResult::Complete
                                                        } else {
                                                            log::trace!(target: "citadel", "Other inbound groups being processed; patiently awaiting group {group_id}");
                                                            QueueWorkerResult::Incomplete
                                                        }
                                                    } else {
                                                        // The inbound group is still receiving, and it hasn't expired. Keep polling
                                                        QueueWorkerResult::Incomplete
                                                    }
                                                } else {
                                                    // group has not started; previous group is still transferring. Do no interrupt transfer
                                                    QueueWorkerResult::Incomplete
                                                }
                                            } else {
                                                // has been removed, thus is complete
                                                QueueWorkerResult::Complete
                                            }
                                        });
                                    }

                                    let group_header_ack =
                                        packet_crafter::group::craft_group_header_ack(
                                            &ratchet,
                                            header.group.get(),
                                            resp_target_cid,
                                            object_id,
                                            ticket,
                                            initial_wave_window,
                                            false,
                                            timestamp,
                                            security_level,
                                        );
                                    Ok(PrimaryProcessorResult::ReplyToSender(group_header_ack))
                                }
                            }
                        }

                        packet_flags::cmd::aux::group::GROUP_HEADER_ACK => {
                            log::trace!(target: "citadel", "RECV GROUP HEADER ACK");
                            match validation::group::validate_header_ack(&payload) {
                                Some(GroupHeaderAck::ReadyToReceive {
                                    initial_window,
                                    fast_msg,
                                    object_id,
                                }) => {
                                    // we need to begin sending the data
                                    // valid and ready to accept!
                                    let initial_wave_window = if udp_mode == UdpMode::Disabled {
                                        None
                                    } else {
                                        initial_window
                                    };

                                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                                    let peer_cid = header.session_cid.get();
                                    let group_id = header.group.get();

                                    if resp_target_cid != C2S_IDENTITY_CID {
                                        // If there is a pending disconnect, we need to make sure the session gets dropped until after all packets get processed
                                        let vconn = return_if_none!(
                                            state_container
                                                .active_virtual_connections
                                                .get(&resp_target_cid),
                                            "Vconn not loaded"
                                        );
                                        vconn
                                            .last_delivered_message_timestamp
                                            .set(Some(Instant::now()));
                                    }

                                    // TODO: make the below function return a result, not bools
                                    if state_container.on_group_header_ack_received(
                                        peer_cid,
                                        group_id,
                                        object_id,
                                        initial_wave_window,
                                        fast_msg,
                                    ) {
                                        Ok(PrimaryProcessorResult::Void)
                                    } else if udp_mode == UdpMode::Disabled {
                                        Ok(PrimaryProcessorResult::EndSession(
                                            "TCP sockets disconnected",
                                        ))
                                    } else {
                                        Ok(PrimaryProcessorResult::EndSession(
                                            "UDP sockets disconnected",
                                        ))
                                    }
                                }

                                Some(GroupHeaderAck::NotReady {
                                    fast_msg,
                                    object_id,
                                }) => {
                                    // valid but not ready to accept.
                                    // Possible reasons: too large, target not valid (e.g., not registered, not connected, etc)
                                    //let mut state_container = session.state_container.borrow_mut();
                                    let group = header.group.get();
                                    let key =
                                        GroupKey::new(header.session_cid.get(), group, object_id);
                                    if state_container.outbound_transmitters.remove(&key).is_none()
                                    {
                                        log::error!(target: "citadel", "Unable to remove outbound transmitter for group {group} (non-existent)");
                                    }
                                    //std::mem::drop(state_container);

                                    if !fast_msg {
                                        let ticket = header.context_info.get();
                                        log::trace!(target: "citadel", "Header ACK was valid, but the receiving end is not receiving the packet at this time. Clearing local memory ...");
                                        session.send_to_kernel(
                                            NodeResult::OutboundRequestRejected(
                                                OutboundRequestRejected {
                                                    ticket: ticket.into(),
                                                    message_opt: Some(Vec::from(
                                                        "Adjacent node unable to accept request",
                                                    )),
                                                },
                                            ),
                                        )?;
                                    }

                                    Ok(PrimaryProcessorResult::Void)
                                }

                                None => {
                                    // invalid packet
                                    log::error!(target: "citadel", "Invalid GROUP HEADER ACK");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            }
                        }

                        packet_flags::cmd::aux::group::WAVE_ACK => {
                            log::trace!(target: "citadel", "RECV WAVE ACK");
                            match validation::group::validate_wave_ack(&payload) {
                                Some(WaveAck { range }) => {
                                    if range.is_some() {
                                        log::trace!(target: "citadel", "WAVE_ACK implies window completion");
                                    }

                                    // the window is done. Since this node is the transmitter, we then make a call to begin sending the next wave
                                    if !state_container
                                        .on_wave_ack_received(ratchet.get_cid(), &header)
                                    {
                                        if udp_mode == UdpMode::Disabled {
                                            log::error!(target: "citadel", "There was an error sending the TCP window; Cancelling connection");
                                        } else {
                                            log::error!(target: "citadel", "There was an error sending the UDP window; Cancelling connection");
                                        }

                                        Ok(PrimaryProcessorResult::EndSession(
                                            "Sockets disconnected",
                                        ))
                                    } else {
                                        log::trace!(target: "citadel", "Successfully sent next window in response to WAVE ACK");
                                        Ok(PrimaryProcessorResult::Void)
                                    }
                                }

                                None => {
                                    log::error!(target: "citadel", "Error validating WAVE_ACK");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            }
                        }

                        _ => {
                            log::trace!(target: "citadel", "Primary port GROUP packet has an invalid auxiliary command. Dropping");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                _ => {
                    log::warn!(target: "citadel", "Packet failed AES-GCM validation stage (self node: {})", session.is_server.if_true("server").if_false("client"));
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }
    }
}

#[inline]
pub(super) fn get_orientation_safe_ratchet<R: Ratchet>(
    header_entropy_bank_vers: u32,
    state_container: &dyn ExpectedInnerTarget<StateContainerInner<R>>,
    proxy_cid_info: Option<(u64, u64)>,
) -> Option<R> {
    if let Some((original_session_cid, _original_target_cid)) = proxy_cid_info {
        // since this conn was proxied, we need to go into the virtual conn layer to get the peer session crypto. HOWEVER:
        // In the case that a packet is proxied back to the source, the adjacent endpoint inscribes this node's cid
        // inside the target_cid (that way the packet routes correctly to this node). However, this is problematic here
        // since we use the original implicated CID
        if let Some(vconn) = state_container
            .active_virtual_connections
            .get(&original_session_cid)
        {
            //log::trace!(target: "citadel", "[Peer StackedRatchet] v{} from vconn w/ {}", header_entropy_bank_vers, original_session_cid);
            vconn.get_endpoint_ratchet(Some(header_entropy_bank_vers))
        } else {
            log::warn!(target: "citadel", "Unable to find vconn for {original_session_cid}. Unable to process primary group packet");
            None
        }
    } else {
        // since this was not proxied, use the ordinary pqc and entropy_bank
        if !state_container.state.is_connected() {
            state_container.pre_connect_state.generated_ratchet.clone()
        } else {
            state_container
                .get_endpoint_container(C2S_IDENTITY_CID)
                .ok()?
                .ratchet_manager
                .get_ratchet(Some(header_entropy_bank_vers))
        }
    }
}

/// returns the relative `resp_target_cid`
pub fn get_resp_target_cid(virtual_target: &VirtualConnectionType) -> Option<u64> {
    match virtual_target {
        VirtualConnectionType::LocalGroupPeer {
            session_cid,
            peer_cid: _target_cid,
        } => {
            // by logic of the network, target_cid must equal this node's CID
            // since we have entered this process function
            //debug_assert_eq!(sess_session_cid, target_cid);
            //debug_assert_eq!(target_cid_header, target_cid);
            Some(*session_cid)
        }

        VirtualConnectionType::LocalGroupServer {
            session_cid: _session_cid,
        } => {
            // Since this is the receiving node, and we are already in a valid connection, return true
            Some(0) // ZERO, since we don't use ordinary p2p encryption
        }

        _ => {
            log::error!(target: "citadel", "HyperWAN functionality is not yet implemented");
            None
        }
    }
}

pub fn get_resp_target_cid_from_header(header: &HdpHeader) -> u64 {
    if header.target_cid.get() != C2S_IDENTITY_CID {
        header.session_cid.get()
    } else {
        C2S_IDENTITY_CID
    }
}

/// Returns the virtual connection type for the response target cid. Is relative to the current node, not the receiving node
pub fn get_v_conn_from_header(header: &HdpHeader) -> VirtualConnectionType {
    let target_cid = header.session_cid.get();
    let session_cid = header.target_cid.get();
    if target_cid != C2S_IDENTITY_CID {
        VirtualConnectionType::LocalGroupPeer {
            session_cid,
            peer_cid: target_cid,
        }
    } else {
        VirtualConnectionType::LocalGroupServer { session_cid }
    }
}
