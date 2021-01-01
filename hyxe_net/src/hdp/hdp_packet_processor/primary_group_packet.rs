use super::includes::*;
use crate::hdp::state_container::{StateContainerInner, GroupKey, FileKey};
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::hdp::session_queue_handler::QueueWorkerResult;
use atomic::Ordering;
use crate::hdp::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer, HyperRatchetConstructor};

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

        match validation::aead::validate_custom(&hyper_ratchet, &*header, payload) {
            Some((header, payload)) => {
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

                                    let resp_target_cid = recipient_valid_gate(&virtual_target, wrap_inner_mut!(state_container))?;

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
                                    let group_header_ack = hdp_packet_crafter::group::craft_group_header_ack(&hyper_ratchet, object_id, header.group.get(), resp_target_cid, ticket,initial_wave_window, false, timestamp, None);
                                    PrimaryProcessorResult::ReplyToSender(group_header_ack)
                                }

                                GroupHeader::FastMessage(plaintext, virtual_target, transfer) => {
                                    // Here, we do not go through all the fiasco like above. We just forward the message to the kernel, then send an ACK
                                    // so that the sending side can be notified of a successful send
                                    let resp_target_cid = recipient_valid_gate(&virtual_target, wrap_inner_mut!(state_container))?;
                                    let object_id = header.wave_id.get();
                                    let ticket = header.context_info.get().into();
                                    let timestamp = session.time_tracker.get_global_time_ns();
                                    let plaintext = SecBuffer::from(plaintext);

                                    if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
                                        // send to channel
                                        if !state_container.forward_data_to_channel_as_endpoint(original_implicated_cid, plaintext) {
                                            log::error!("Unable to forward data to channel (peer: {})", original_implicated_cid);
                                            return PrimaryProcessorResult::Void;
                                        }
                                    } else {
                                        // send to kernel
                                        let implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                                        session.send_to_kernel(HdpServerResult::MessageDelivery(ticket, implicated_cid, plaintext))?;
                                    }

                                    // now, update the keys (if applicable)
                                    let transfer = if let Some(transfer) = transfer {
                                        Some(update_toolset_as_bob(cnac_sess, transfer, header.algorithm, header.drill_version.get() + 1)?)
                                    } else { None };

                                    // finally, return a GROUP_HEADER_ACK
                                    let group_header_ack = hdp_packet_crafter::group::craft_group_header_ack(&hyper_ratchet, object_id, header.group.get(), resp_target_cid, ticket, None, true, timestamp, transfer);
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
                                    if !state_container.on_group_header_ack_received(object_id, peer_cid, group_id, initial_wave_window, transfer, cnac_sess, fast_msg) {
                                        if tcp_only {
                                            PrimaryProcessorResult::EndSession("TCP sockets disconnected")
                                        } else {
                                            PrimaryProcessorResult::EndSession("UDP sockets disconnected")
                                        }
                                    } else {
                                        PrimaryProcessorResult::Void
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
                                match state_container.on_window_tail_received(&hyper_ratchet, state_container_ref, &header,waves_in_window, &session.time_tracker, to_primary_stream) {
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
                log::error!("Packet failed AES-GCM validation stage");
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
                    if !state_container.forward_data_to_channel_as_endpoint(original_implicated_cid, reconstructed_packet) {
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
        // since we use the original implica
        if let Some(vconn) = state_container.active_virtual_connections.get(&original_implicated_cid) {
            vconn.get_endpoint_hyper_ratchet(|hyper_ratchet| {
                hyper_ratchet.clone()
            })
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
pub fn recipient_valid_gate<K: ExpectedInnerTargetMut<StateContainerInner>>(virtual_target: &VirtualConnectionType, state_container: InnerParameterMut<K, StateContainerInner>) -> Option<u64> {
    match virtual_target {
        VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
            // by logic of the network, target_cid must equal this node's CID
            // since we have entered this process function
            //debug_assert_eq!(sess_implicated_cid, target_cid);
            //debug_assert_eq!(target_cid_header, target_cid);
            // the current node must be in a virtual connection with the original implicated_cid
            // the resp_target_cid will be the original sender of this packet, being `implicated_cid`
            // of the deserialized vconn type (order did not flip)
            if state_container.active_virtual_connections.contains_key(implicated_cid) {
                Some(*implicated_cid)
            } else {
                None
            }
        }

        VirtualConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
            // Since this is the receiving node, and we are already in a valid connection, return true
            Some(0) // ZERO, since we don't need proxying
        }

        _ => {
            unimplemented!("HyperWAN functionality is not yet implemented")
        }
    }
}

fn update_toolset_as_bob(cnac: &ClientNetworkAccount, transfer: AliceToBobTransfer<'_>, algorithm: u8, new_drill_vers: u32) -> Option<BobToAliceTransfer> {
    let constructor = HyperRatchetConstructor::new_bob(algorithm, cnac.get_id(), new_drill_vers, transfer)?;
    let transfer = constructor.stage0_bob()?;
    cnac.register_new_hyper_ratchet(constructor.finish()?).ok()?;
    Some(transfer)
}