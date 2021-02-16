use super::includes::*;
use crate::hdp::state_container::{StateContainerInner, GroupKey, FileKey, VirtualConnection};
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::hdp::session_queue_handler::QueueWorkerResult;
use atomic::Ordering;
use crate::hdp::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
use hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet, RatchetType};
use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransferType, ConstructorType};
use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus, EndpointRatchetConstructor};
use crate::functional::IfTrueConditional;
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
use crate::error::NetworkError;
use std::collections::HashMap;
use hyxe_crypt::fcm::fcm_ratchet::{FcmRatchet, FcmAliceToBobTransfer};
use crate::inner_arg::ExpectedInnerTarget;
use crate::fcm::data_structures::FCMMessagePayload;
use hyxe_fs::io::SyncIO;
use crate::hdp::hdp_server::MessageType;

/// This will handle an inbound primary group packet
/// NOTE: Since incorporating the proxy features, if a packet gets to this process closure, it implies the packet
/// has reached its destination. Just need to ensure that intermediary packets get the proper target_cid on the headers that way
/// they proxy
///
/// `proxy_cid_info`: is None if the packets were not proxied, and will thus use the session's pqcrypto to authenticate the data.
/// If `proxy_cid_info` is Some, then a tuple of the original implicated cid (peer cid) and the original target cid (this cid)
/// will be provided. In this case, we must use the virtual conn's crypto
pub fn process(session: &HdpSession, cmd_aux: u8, packet: HdpPacket, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session);

    if session.state != SessionState::Connected {
        log::error!("Group packet dropped; session not connected");
        return PrimaryProcessorResult::Void;
    }

    // Group payloads are not validated in the same way the primary packets are (with the exception of FAST_MSG's in GROUP_HEADERS)
    // While group payloads are typically processed by the wave ports, it is possible
    // that TCP_ONLY mode is engaged, in which case, the packets are funneled through here
    if cmd_aux != packet_flags::cmd::aux::group::GROUP_PAYLOAD {
        let (header, payload, _, _) = packet.decompose();
        let cnac_sess = session.cnac.as_ref()?;
        let mut state_container = inner_mut!(session.state_container);
        // get the proper pqc
        let header_bytes = &header[..];
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        let hyper_ratchet = get_proper_hyper_ratchet(header.drill_version.get(), cnac_sess, &wrap_inner_mut!(state_container), proxy_cid_info)?;
        let security_level = header.security_level.into();
        log::info!("[Peer HyperRatchet] Obtained version {} w/ CID {} (this CID: {})", hyper_ratchet.version(), hyper_ratchet.get_cid(), header.session_cid.get());
        match validation::aead::validate_custom(&hyper_ratchet, &*header, payload) {
            Some((header, payload)) => {
                state_container.meta_expiry_state.on_event_confirmation();

                match cmd_aux {
                    packet_flags::cmd::aux::group::GROUP_HEADER => {
                        log::info!("RECV GROUP HEADER");
                        // keep in mind: The group header is a packet with a standard header containing the ticket in the context_info, but with a payload len in the 8-byte "payload"
                        if let Some(group_header) = validation::group::validate_header(&payload[..], &hyper_ratchet, &header) {
                            match group_header {
                                GroupHeader::Standard(group_receiver_config, virtual_target) => {
                                    // First, check to make sure the virtual target can accept
                                    let object_id = header.wave_id.get();
                                    let ticket = header.context_info.get().into();
                                    let timestamp = session.time_tracker.get_global_time_ns();
                                    //let sess_implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                                    //let target_cid_header = header.target_cid.get();
                                    // for HyperLAN conns, this is true

                                    let resp_target_cid = get_resp_target_cid(&virtual_target)?;

                                    // the below will return None if not ready to accept
                                    let initial_wave_window = state_container.on_group_header_received(&header, group_receiver_config, virtual_target);
                                    if initial_wave_window.is_some() {
                                        // register group timeout device
                                        std::mem::drop(state_container);
                                        let group_id = header.group.get();
                                        let peer_cid = header.session_cid.get();

                                        session.queue_worker.insert_ordinary(group_id as usize, peer_cid, GROUP_EXPIRE_TIME_MS, move |sess| {
                                            let mut state_container = inner_mut!(sess.state_container);
                                            let key = GroupKey::new(peer_cid, group_id);
                                            if let Some(group) = state_container.inbound_groups.get(&key) {
                                                if group.has_begun {
                                                    if group.receiver.has_expired(GROUP_EXPIRE_TIME_MS) {
                                                        if state_container.meta_expiry_state.expired() {
                                                            log::error!("Inbound group {} has expired; removing for {}.", group_id, peer_cid);
                                                            if let Some(group) = state_container.inbound_groups.remove(&key) {
                                                                if group.object_id != 0 {
                                                                    // belongs to a file. Delete file; stop transmission
                                                                    let key = FileKey::new(peer_cid, group.object_id);
                                                                    if let Some(_file) = state_container.inbound_files.remove(&key) {
                                                                        // stop the stream to the HD
                                                                        //file.stream_to_hd.close_channel();
                                                                        log::warn!("File transfer expired");
                                                                        // TODO: Create file FIN
                                                                    }
                                                                }
                                                            }

                                                            QueueWorkerResult::Complete
                                                        } else {
                                                            log::info!("[X-04] Other inbound groups being processed; patiently awaiting group {}", group_id);
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
                                    let group_header_ack = hdp_packet_crafter::group::craft_group_header_ack(&hyper_ratchet, object_id, header.group.get(), resp_target_cid, ticket, initial_wave_window, false, timestamp, KemTransferStatus::Empty, security_level);
                                    PrimaryProcessorResult::ReplyToSender(group_header_ack)
                                }

                                GroupHeader::FastMessage(plaintext, virtual_target, transfer) => {
                                    // Here, we do not go through all the fiasco like above. We just forward the message to the kernel, then send an ACK
                                    // so that the sending side can be notified of a successful send
                                    let resp_target_cid = get_resp_target_cid(&virtual_target)?;
                                    let object_id = header.wave_id.get();
                                    let ticket = header.context_info.get().into();
                                    let timestamp = session.time_tracker.get_global_time_ns();
                                    let plaintext = SecBuffer::from(plaintext);
                                    // we call this to ensure a flood of these packets doesn't cause ordinary groups from being dropped

                                    if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
                                        // send to channel
                                        if !state_container.forward_data_to_channel_as_endpoint(original_implicated_cid, MessageType::Default(plaintext)) {
                                            log::error!("Unable to forward data to channel (peer: {})", original_implicated_cid);
                                            return PrimaryProcessorResult::Void;
                                        }
                                    } else {
                                        // send to kernel
                                        let implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                                        session.send_to_kernel(HdpServerResult::MessageDelivery(ticket, implicated_cid, plaintext))?;
                                    }

                                    // now, update the keys (if applicable)
                                    let transfer = attempt_kem_as_bob(resp_target_cid, &header, transfer.map(AliceToBobTransferType::Default), &mut state_container.active_virtual_connections, cnac_sess)?;

                                    let group_header_ack = hdp_packet_crafter::group::craft_group_header_ack(&hyper_ratchet, object_id, header.group.get(), resp_target_cid, ticket, None, true, timestamp, transfer, security_level);
                                    PrimaryProcessorResult::ReplyToSender(group_header_ack)
                                }
                                GroupHeader::Fcm(encrypted_message, fcm_ratchet_vers, v_target, transfer_base, transfer_fcm) => {
                                    log::info!("[FCM] about to process FCM GroupHeader ...");

                                    match send_fcm_message_as_server(encrypted_message, v_target, transfer_fcm, cnac_sess, &session, &hyper_ratchet, fcm_ratchet_vers, &header) {
                                        Ok(_) => {
                                            log::info!("[FCM] success executing send_fcm_message_as_server");
                                            // TODO: Provide response back to client, even though they may be offline by now (IDEA: Send response packet to sess_cnac's FCM? Response should be small too since it's smaller than the 2KB public key exchange)
                                        }

                                        Err(err) => {
                                            log::warn!("[FCM] error executing send_fcm_message_as_server: {:?}", err);
                                            // TODO: Provide response back to client, even though they may be offline by now
                                        }
                                    }

                                    // now, update base ratchet
                                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                                    let object_id = header.wave_id.get();
                                    let ticket = header.context_info.get().into();
                                    let timestamp = session.time_tracker.get_global_time_ns();

                                    let transfer = attempt_kem_as_bob(resp_target_cid, &header, transfer_base.map(AliceToBobTransferType::Default), &mut state_container.active_virtual_connections, cnac_sess)?;

                                    let group_header_ack = hdp_packet_crafter::group::craft_group_header_ack(&hyper_ratchet, object_id, header.group.get(), resp_target_cid, ticket, None, true, timestamp, transfer, security_level);

                                    PrimaryProcessorResult::ReplyToSender(group_header_ack)
                                }
                            }
                        } else {
                            log::error!("Invalid GROUP_HEADER");
                            PrimaryProcessorResult::Void
                        }
                    }

                    packet_flags::cmd::aux::group::GROUP_HEADER_ACK => {
                        log::info!("RECV GROUP HEADER ACK");
                        match validation::group::validate_header_ack(&payload) {
                            Some(GroupHeaderAck::ReadyToReceive { initial_window, transfer, fast_msg }) => {
                                let timestamp = session.time_tracker.get_global_time_ns();
                                // we need to begin sending the data
                                // valid and ready to accept!
                                let tcp_only = session.tcp_only;
                                let initial_wave_window = if tcp_only {
                                    None
                                } else {
                                    initial_window
                                };

                                // A weird exception for obj_id location .. usually in context info, but in wave if for this unique case
                                let peer_cid = header.session_cid.get();
                                //let mut state_container = session.state_container.borrow_mut();
                                let object_id = header.wave_id.get();
                                let group_id = header.group.get();

                                let target_cid = header.target_cid.get();
                                let needs_truncate = transfer.requires_truncation();

                                if state_container.on_group_header_ack_received(object_id, peer_cid, target_cid, group_id, initial_wave_window, transfer, fast_msg, cnac_sess) {
                                    log::info!("[Toolset Update] Needs truncation? {:?}", &needs_truncate);
                                    // now, we need to do one last thing. If the previous function performed an update inside the toolset, it is also possible that we need to truncate
                                    if let Some(truncate_vers) = needs_truncate {
                                        // we need to send a truncate packet
                                        let target_cid = if target_cid != ENDPOINT_ENCRYPTION_OFF { peer_cid } else { ENDPOINT_ENCRYPTION_OFF };
                                        let truncate_packet = hdp_packet_crafter::do_drill_update::craft_truncate(&hyper_ratchet, truncate_vers, target_cid, timestamp, security_level);
                                        log::info!("About to send TRUNCATE packet to remove v {} | HR v {} | HR CID {}", truncate_vers, hyper_ratchet.version(), hyper_ratchet.get_cid());
                                        PrimaryProcessorResult::ReplyToSender(truncate_packet)
                                    } else {
                                        PrimaryProcessorResult::Void
                                    }
                                } else {
                                    if tcp_only {
                                        PrimaryProcessorResult::EndSession("TCP sockets disconnected")
                                    } else {
                                        PrimaryProcessorResult::EndSession("UDP sockets disconnected")
                                    }
                                }
                            }

                            Some(GroupHeaderAck::NotReady { fast_msg }) => {
                                // valid but not ready to accept.
                                // Possible reasons: too large, target not valid (e.g., not registered, not connected, etc)
                                //let mut state_container = session.state_container.borrow_mut();
                                let group = header.group.get();
                                let key = GroupKey::new(header.session_cid.get(), group);
                                if let None = state_container.outbound_transmitters.remove(&key) {
                                    log::error!("Unable to remove outbound transmitter for group {} (non-existent)", group);
                                }
                                std::mem::drop(state_container);

                                if !fast_msg {
                                    let ticket = header.context_info.get();
                                    log::info!("Header ACK was valid, but the receiving end is not receiving the packet at this time. Clearing local memory ...");
                                    session.send_to_kernel(HdpServerResult::OutboundRequestRejected(ticket.into(), Some(Vec::from("Adjacent node unable to accept request"))))?;
                                }

                                PrimaryProcessorResult::Void
                            }

                            None => {
                                // invalid packet
                                log::error!("Invalid GROUP HEADER ACK");
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    // This gets sent by Alice after she sends her window over. It tells this end, Bob, that he can expect to get the packets
                    // soon. Even though the GROUP_WINDOW_TAIL is sent AFTER the payload packets, it is possible that payload packets arrive
                    // AFTER the GROUP_WINDOW_TAIL. As such, we must define "soon". If the window is finished upon arrival of the WINDOW_TAIL, no reason waiting. However,
                    // if the window is not finished ... we wait for a duration equal to twice the ping. We then check again. If the window is
                    // received, we don't have to do anything since the WAVE_ACKs will automatically be sent back to the sender (the last WAVE_ACK
                    // will contain the range of the next window). If, however, the window is still not yet done, we assume that packet loss occurred.
                    // From there, we send a set of DO_WAVE_RETRANSMISSIONS. At that point, nothing more needs to be done from the trigger caused by the
                    // GROUP_WINDOW_TAIL
                    //
                    // Other notes: If the first DO_WAVE_RETRANSMISSIONS don't work, the internal session timer will automatically send the DO_WAVE_RETRANSMISSIONS
                    // If those fails too, then the group is eventually dropped after the expiration occurs
                    packet_flags::cmd::aux::group::GROUP_WINDOW_TAIL => {
                        log::info!("RECV GROUP WINDOW TAIL");
                        match validation::group::validate_window_tail(&header, &payload) {
                            Some(waves_in_window) => {
                                let to_primary_stream = session.to_primary_stream.as_ref()?;
                                let ref state_container_ref = session.state_container;
                                match state_container.on_window_tail_received(&hyper_ratchet, state_container_ref, &header, waves_in_window, &session.time_tracker, to_primary_stream) {
                                    true => {
                                        PrimaryProcessorResult::Void
                                    }

                                    false => {
                                        PrimaryProcessorResult::Void
                                    }
                                }
                            }

                            None => {
                                log::info!("Error validating WINDOW TAIL");
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    // This node is being told to retransmit a set of packets (this node is Alice)
                    packet_flags::cmd::aux::group::WAVE_DO_RETRANSMISSION => {
                        log::info!("RECV WAVE DO RETRANSMISSION");
                        match validation::group::validate_wave_do_retransmission(&payload) {
                            Ok(_) => {
                                // The internal session timer will handle the outbound dispatch of packets
                                // once
                                state_container.on_wave_do_retransmission_received(&hyper_ratchet, &header, &payload);
                                PrimaryProcessorResult::Void
                            }

                            Err(err) => {
                                log::error!("Error validating WAVE_DO_RETRANSMISSION: {}", err.to_string());
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    // The
                    packet_flags::cmd::aux::group::WAVE_ACK => {
                        log::info!("RECV WAVE ACK");
                        match validation::group::validate_wave_ack(&payload) {
                            Some(WaveAck { range }) => {
                                let tcp_only = session.tcp_only;

                                if range.is_some() {
                                    log::info!("WAVE_ACK implies window completion!");
                                }

                                // the window is done. Since this node is the transmitter, we then make a call to begin sending the next wave
                                if !state_container.on_wave_ack_received(hyper_ratchet.get_cid(), &header, tcp_only, range) {
                                    if tcp_only {
                                        log::error!("There was an error sending the TCP window; Cancelling connection");
                                    } else {
                                        log::error!("There was an error sending the UDP window; Cancelling connection");
                                    }

                                    PrimaryProcessorResult::EndSession("Sockets disconnected")
                                } else {
                                    log::info!("Successfully sent next window in response to WAVE ACK");
                                    PrimaryProcessorResult::Void
                                }
                            }

                            None => {
                                log::error!("Error validating WAVE_ACK");
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    _ => {
                        log::trace!("Primary port GROUP packet has an invalid auxiliary command. Dropping");
                        PrimaryProcessorResult::Void
                    }
                }
            }

            _ => {
                log::error!("Packet failed AES-GCM validation stage (self node: {})", session.is_server.if_true("server").if_false("client"));
                PrimaryProcessorResult::Void
            }
        }
    } else {
        //log::info!("RECV [TCP] GROUP PAYLOAD");
        let (header, payload) = packet.parse()?;
        if payload.len() < 2 {
            log::error!("sub-2-length wave packet payload; dropping");
            return PrimaryProcessorResult::Void;
        }
        //log::info!("[TCP-WAVE] Packet received has {} bytes", payload.len());
        let v_src_port = payload[0] as u16;
        let v_recv_port = payload[1] as u16;
        let payload = &payload[2..];

        match super::wave_group_packet::process(&mut wrap_inner_mut!(session), v_src_port, v_recv_port, &header, payload, proxy_cid_info) {
            GroupProcessorResult::SendToKernel(ticket, reconstructed_packet) => {
                if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
                    // send to channel
                    let mut state_container = inner_mut!(session.state_container);
                    if !state_container.forward_data_to_channel_as_endpoint(original_implicated_cid, MessageType::Default(reconstructed_packet)) {
                        log::error!("Unable to forward data to channel (peer: {})", original_implicated_cid);
                    }
                    PrimaryProcessorResult::Void
                } else {
                    // send to kernel
                    let implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                    session.send_to_kernel(HdpServerResult::MessageDelivery(ticket, implicated_cid, reconstructed_packet))?;
                    PrimaryProcessorResult::Void
                }
            }

            res => res.into()
        }
    }
}

#[inline]
pub(super) fn get_proper_hyper_ratchet<K: ExpectedInnerTargetMut<StateContainerInner>>(header_drill_vers: u32, sess_cnac: &ClientNetworkAccount, state_container: &InnerParameterMut<K, StateContainerInner>, proxy_cid_info: Option<(u64, u64)>) -> Option<HyperRatchet> {
    if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
        // since this conn was proxied, we need to go into the virtual conn layer to get the peer session crypto. HOWEVER:
        // In the case that a packet is proxied back to the source, the adjacent endpoint inscribes this node's cid
        // inside the target_cid (that way the packet routes correctly to this node). However, this is problematic here
        // since we use the original implicated CID
        if let Some(vconn) = state_container.active_virtual_connections.get(&original_implicated_cid) {
            log::info!("[Peer HyperRatchet] v{} from vconn w/ {} (local username: {})", header_drill_vers, original_implicated_cid, sess_cnac.get_username());
            vconn.borrow_endpoint_hyper_ratchet(Some(header_drill_vers)).cloned()
        } else {
            log::error!("Unable to find vconn for {}. Unable to process primary group packet", original_implicated_cid);
            return None;
        }
    } else {
        // since this was not proxied, use the ordinary pqc and drill

        let hyper_ratchet = sess_cnac.get_hyper_ratchet(Some(header_drill_vers))?;
        Some(hyper_ratchet)
    }
}

/// returns the relative `resp_target_cid`
pub fn get_resp_target_cid(virtual_target: &VirtualConnectionType) -> Option<u64> {
    match virtual_target {
        VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
            // by logic of the network, target_cid must equal this node's CID
            // since we have entered this process function
            //debug_assert_eq!(sess_implicated_cid, target_cid);
            //debug_assert_eq!(target_cid_header, target_cid);
            Some(*implicated_cid)
        }

        VirtualConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
            // Since this is the receiving node, and we are already in a valid connection, return true
            Some(0) // ZERO, since we don't use ordinary p2p encryption
        }

        _ => {
            unimplemented!("HyperWAN functionality is not yet implemented")
        }
    }
}

pub fn get_resp_target_cid_from_header(header: &LayoutVerified<&[u8], HdpHeader>) -> u64 {
    if header.target_cid.get() != ENDPOINT_ENCRYPTION_OFF {
        header.session_cid.get()
    } else {
        ENDPOINT_ENCRYPTION_OFF
    }
}

pub enum ToolsetUpdate<'a, R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    E2E { crypt: &'a mut PeerSessionCrypto<R>, local_cid: u64 },
    SessCNAC(&'a ClientNetworkAccount<R, Fcm>),
    FCM { cnac: &'a ClientNetworkAccount<R, Fcm>, peer_cid: u64 }
}

impl<R: Ratchet, Fcm: Ratchet> ToolsetUpdate<'_, R, Fcm> {
    pub(crate) fn update(&mut self, constructor: ConstructorType<R, Fcm>, local_is_alice: bool) -> Result<KemTransferStatus, ()> {
        match self {
            ToolsetUpdate::E2E { crypt, local_cid } => {
                let constructor = constructor.assume_default().ok_or(())?;
                crypt.update_sync_safe(constructor, local_is_alice, *local_cid)
            }

            // TODO: Perfect concurrent updating above, then make the below account for the possibility of both server/client making changes
            ToolsetUpdate::SessCNAC(cnac) => {
                let constructor = constructor.assume_default().ok_or(())?;
                cnac.visit_mut(|mut inner| {
                    let local_cid = inner.cid;
                    inner.crypt_container.update_sync_safe(constructor, local_is_alice, local_cid)
                })
            }

            ToolsetUpdate::FCM { cnac, peer_cid } => {
                let constructor = constructor.assume_fcm().ok_or(())?;
                cnac.visit_mut(|mut inner| {
                    let local_cid = inner.cid;
                    let container = inner.fcm_crypt_container.get_mut(peer_cid).ok_or(())?;
                    container.update_sync_safe(constructor, local_is_alice, local_cid)
                })
            }
        }
    }

    pub(crate) fn deregister(&mut self, version: u32) -> Result<(), NetworkError> {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => {
                crypt.deregister_oldest_hyper_ratchet(version).map_err(|err| NetworkError::Generic(err.to_string()))
            }

            ToolsetUpdate::SessCNAC(cnac) => {
                cnac.deregister_oldest_hyper_ratchet(version).map_err(|err| NetworkError::Generic(err.to_string()))
            }

            ToolsetUpdate::FCM { cnac, peer_cid } => {
                cnac.visit_mut(|mut inner| {
                    let container = inner.fcm_crypt_container.get_mut(peer_cid).ok_or(NetworkError::InternalError("FCM container missing"))?;
                    container.deregister_oldest_hyper_ratchet(version).map_err(|err| NetworkError::Generic(err.to_string()))
                })
            }
        }
    }

    /// Unlocks the internal state, allowing future upgrades to the system. Returns the latest hyper ratchet
    pub(crate) fn unlock(self) -> Option<RatchetType<R, Fcm>> {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => {
                crypt.update_in_progress = false;
                log::info!("Successfully toggled update_in_progress");
                Some(RatchetType::Default(crypt.get_hyper_ratchet(None).cloned()?))
            }

            ToolsetUpdate::SessCNAC(cnac) => {
                cnac.visit_mut(|mut inner| {
                    inner.crypt_container.update_in_progress = false;
                    Some(RatchetType::Default(inner.crypt_container.get_hyper_ratchet(None).cloned()?))
                })
            }

            ToolsetUpdate::FCM { cnac, peer_cid, .. } => {
                cnac.visit_mut(|mut inner| {
                    let mut container = inner.fcm_crypt_container.get_mut(&peer_cid)?;
                    container.update_in_progress = false;
                    Some(RatchetType::Fcm(container.get_hyper_ratchet(None).cloned()?))
                })
            }
        }
    }

    pub(crate) fn get_local_cid(&self) -> u64 {
        match self {
            ToolsetUpdate::E2E { local_cid, .. } => *local_cid,
            ToolsetUpdate::SessCNAC(cnac) => cnac.get_cid(),
            ToolsetUpdate::FCM { cnac, .. } => cnac.get_cid()
        }
    }
}

/// peer_cid: from header.session_cid
/// target_cid: from header.target_cid
///
/// Returns: Ok(latest_hyper_ratchet)
// TODO: Figure out if FCM is usable here. As of now, it isn't. Consider adding an FCM flag to the message header
pub(crate) fn attempt_kem_as_alice_finish<R: Ratchet, Fcm: Ratchet>(peer_cid: u64, target_cid: u64, transfer: KemTransferStatus, vconns: &mut HashMap<u64, VirtualConnection<R>>, constructor: Option<ConstructorType<R, Fcm>>, cnac_sess: &ClientNetworkAccount<R, Fcm>) -> Result<Option<RatchetType<R, Fcm>>, ()> {
    let mut toolset_update_method = if target_cid != ENDPOINT_ENCRYPTION_OFF {
        let crypt = &mut vconns.get_mut(&peer_cid).ok_or(())?.endpoint_container.as_mut().ok_or(())?.endpoint_crypto;
        ToolsetUpdate::E2E { crypt, local_cid: target_cid }
    } else {
        ToolsetUpdate::SessCNAC(cnac_sess)
    };

    let requires_truncation = transfer.requires_truncation();

    match transfer {
        KemTransferStatus::Some(transfer, ..) => {
            if let Some(mut constructor) = constructor {
                if let None = constructor.stage1_alice(transfer) {
                    log::error!("Unable to construct hyper ratchet");
                    return Err(()); // return true, otherwise, the session ends
                }

                if let Err(_) = toolset_update_method.update(constructor, true) {
                    log::error!("Unable to update container (X-01)");
                    return Err(());
                }

                if let Some(version) = requires_truncation {
                    if let Err(err) = toolset_update_method.deregister(version) {
                        log::error!("[Toolset Update] Unable to update Alice's toolset: {:?}", err);
                        return Err(());
                    }
                }

                Ok(Some(toolset_update_method.unlock().ok_or(())?))
            } else {
                log::warn!("No constructor, yet, KemTransferStatus is Some??");
                Ok(None)
            }
        }

        KemTransferStatus::Omitted => {
            log::warn!("KEM was omitted (is adjacent node's hold not being released (unexpected), or tight concurrency (expected)?)");
            Ok(Some(toolset_update_method.unlock().ok_or(())?))
        }

        // in this case, wtf? insomnia OP
        KemTransferStatus::StatusNoTransfer(_status) => {
            log::error!("Unaccounted program logic @ StatusNoTransfer");
            std::process::exit(-1);
        }

        _ => {
            Ok(None)
        }
    }
}

// TODO: Figure out FCM
pub(crate) fn attempt_kem_as_bob<R: Ratchet>(resp_target_cid: u64, header: &LayoutVerified<&[u8], HdpHeader>, transfer: Option<AliceToBobTransferType<'_>>, vconns: &mut HashMap<u64, VirtualConnection>, cnac_sess: &ClientNetworkAccount<R>) -> Option<KemTransferStatus> {
    if let Some(transfer) = transfer {
        if resp_target_cid != ENDPOINT_ENCRYPTION_OFF {
            let crypt = &mut vconns.get_mut(&resp_target_cid)?.endpoint_container.as_mut()?.endpoint_crypto;
            let method = ToolsetUpdate::E2E { crypt, local_cid: header.target_cid.get() };
            update_toolset_as_bob(method, transfer, header.algorithm)
        } else {
            let method = ToolsetUpdate::SessCNAC(cnac_sess);
            update_toolset_as_bob(method, transfer, header.algorithm)
        }
    } else {
        Some(KemTransferStatus::Empty)
    }
}

fn update_toolset_as_bob<R: Ratchet>(mut update_method: ToolsetUpdate<'_, R>, transfer: AliceToBobTransferType<'_>, algorithm: u8) -> Option<KemTransferStatus> {
        let cid = update_method.get_local_cid();
        let new_version = transfer.get_declared_new_version();
        let constructor = R::Constructor::new_bob(algorithm, cid, new_version, transfer)?;
        Some(update_method.update(ConstructorType::Default(constructor), false).ok()?)
}

/// In order for client A to send a message to client B, client B needs to have a reg_id inside their CNAC. As such, client B does not have to be online, however, client B is required to connect to the server at least once with its reg id.
/// the reg id is set at connect instead of registration because the fcm reg id may change at the app-level.
///
/// Supposing client B has their ID ready, client A must next ensure that they are normally p2p registered to each other.
///
/// So long as client B has a fcm reg id, and client A is a mutual to client B, then A can send to B
///
/// Since we are the server here, we don't interact with the endpoint container
fn send_fcm_message_as_server<R: Ratchet, Fcm: Ratchet>(encrypted_message: Vec<u8>, v_target: VirtualConnectionType, fcm_transfer: Option<FcmAliceToBobTransfer<'_>>, cnac: &ClientNetworkAccount<R, Fcm>, sess: &dyn ExpectedInnerTarget<HdpSessionInner>, hyper_ratchet: &R, fcm_ratchet_vers: u32, header: &LayoutVerified<&[u8], HdpHeader>) -> Result<(), NetworkError> {
    // first, check to see they are mutuals
    log::info!("Obtaining FCM reg id of peer {}", v_target.get_target_cid());
    if cnac.hyperlan_peer_exists(v_target.get_target_cid()) {
        let reg_id = sess.account_manager.visit_cnac(v_target.get_target_cid(), |peer_cnac| {
            peer_cnac.visit(|peer_inner| {
                peer_inner.fcm_reg_id.clone()
            })
        }).ok_or(NetworkError::InvalidExternalRequest("Peer cannot receive FCM messages at this time"))?;

        log::info!("[FCM] Peer {} reg id: {}", v_target.get_target_cid(), &reg_id);
        // At this point, both conditions are met. We can now send to FCM
        let fcm = sess.fcm_server_conn.clone().ok_or(NetworkError::InvalidExternalRequest("The server is not configured to handle FCM requests"))?;
        let fcm_packet = FCMMessagePayload::new(cnac.get_cid(), v_target.get_target_cid(), header.group.get(), fcm_ratchet_vers, encrypted_message, fcm_transfer.serialize_to_vector().map_err(|err| NetworkError::Generic(err.to_string()))?);
        let _to_primary_stream = sess.to_primary_stream.clone().unwrap();
        let _hyper_ratchet = hyper_ratchet.clone();
        let _object_id = header.wave_id.get();
        // TODO future: handle base ratchet update

        let task = async move {
            match fcm.send_message(reg_id, fcm_packet).await {
                Ok(_resp) => {
                    log::info!("[FCM] Success sending message to FCM service");
                }

                Err(err) => {
                    log::warn!("[FCM] send_message failed: {:?}", &err);
                }
            }
        };

        spawn!(task);
        Ok(())
    } else {
        Err(NetworkError::InvalidExternalRequest("Requested peer is not a mutual to the session client"))
    }
}