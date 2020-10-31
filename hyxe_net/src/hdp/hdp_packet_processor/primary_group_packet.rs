use super::includes::*;
use crate::hdp::state_container::{StateContainerInner, GroupKey, FileKey};
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::hdp::session_queue_handler::QueueWorkerResult;
use std::sync::Arc;
use atomic::Ordering;

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

    // Group payloads are not validated in the same way the primary packets are
    // While group payloads are typically processed by the wave ports, it is possible
    // that TCP_ONLY mode is engaged, in which case, the packets are funneled through here
    if cmd_aux != packet_flags::cmd::aux::group::GROUP_PAYLOAD {
        let (header, payload, _, _) = packet.decompose();
        let pqc_sess = session.post_quantum.as_ref()?;
        let cnac_sess = session.cnac.as_ref()?;
        let mut state_container = inner_mut!(session.state_container);
        // get the proper pqc
        let header_bytes = &header[..];
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        let (pqc, drill) = get_proper_pqc_and_drill(header.drill_version.get(), cnac_sess, pqc_sess, & wrap_inner_mut!(state_container), proxy_cid_info)?;

        match validation::group::validate(&drill, &pqc, header_bytes, payload) {
            Some(payload) => {
                match cmd_aux {
                    packet_flags::cmd::aux::group::GROUP_HEADER => {
                        log::info!("RECV GROUP HEADER");
                        // keep in mind: The group header is a packet with a standard header containing the ticket in the context_info, but with a payload len in the 8-byte "payload"
                        match validation::group::validate_header(&header, &payload) {
                            Some((group_receiver_config, virtual_target)) => {
                                // First, check to make sure the virtual target can accept
                                let object_id = header.wave_id.get();
                                let ticket = header.context_info.get().into();
                                let timestamp = session.time_tracker.get_global_time_ns();
                                let sess_implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                                let target_cid_header = header.target_cid.get();
                                // for HyperLAN conns, this is true

                                //let mut state_container = session.state_container.borrow_mut();
                                let (recipient_valid, resp_target_cid) = match virtual_target {
                                    VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                        // by logic of the network, target_cid must equal this node's CID
                                        // since we have entered this process function
                                        debug_assert_eq!(sess_implicated_cid, target_cid);
                                        debug_assert_eq!(target_cid_header, target_cid);
                                        // the current node must be in a virtual connection with the original implicated_cid
                                        // the resp_target_cid will be the original sender of this packet, being `implicated_cid`
                                        // of the deserialized vconn type (order did not flip)
                                        (state_container.active_virtual_connections.contains_key(&implicated_cid), implicated_cid)
                                    }

                                    VirtualConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                                        // Since this is the receiving node, and we are already in a valid connection, return true
                                        (true, 0) // ZERO, since we don't need proxying
                                    }

                                    _ => {
                                        unimplemented!("HyperWAN functionality is not yet implemented")
                                    }
                                };


                                let group_header_ack = if recipient_valid {
                                    // the below will return None if not ready to accept
                                    let initial_wave_window = state_container.on_group_header_received(&header, &drill, group_receiver_config, virtual_target);
                                    if initial_wave_window.is_some() {
                                        // register group timeout device
                                        std::mem::drop(state_container);
                                        let group_id = header.group.get();
                                        let peer_cid = header.session_cid.get();
                                        session.queue_worker.insert_ordinary(group_id as usize, peer_cid,GROUP_EXPIRE_TIME_MS, move |sess| {
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
                                                                if let Some(file) = state_container.inbound_files.remove(&key) {
                                                                    // stop the stream to the HD
                                                                    file.stream_to_hd.close_channel();
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
                                        })
                                    }
                                    hdp_packet_crafter::group::craft_group_header_ack::<&[u8]>(&pqc, object_id, header.group.get(), resp_target_cid, ticket, &drill, initial_wave_window, None, timestamp)
                                } else {
                                    hdp_packet_crafter::group::craft_group_header_ack(&pqc, object_id, header.group.get(), resp_target_cid, ticket, &drill, None, Some("Requested peer is not connected"), timestamp)
                                };

                                PrimaryProcessorResult::ReplyToSender(group_header_ack)
                            }

                            None => {
                                log::error!("Error validating GROUP HEADER");
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    packet_flags::cmd::aux::group::GROUP_HEADER_ACK => {
                        log::info!("RECV GROUP HEADER ACK");
                        match validation::group::validate_header_ack(&payload) {
                            Some((true, initial_wave_window, _message)) => {
                                // valid and ready to accept!
                                let tcp_only = session.tcp_only;
                                let initial_wave_window = if tcp_only {
                                    None
                                } else {
                                    Some(initial_wave_window)
                                };

                                let to_primary_stream = session.to_primary_stream.as_ref()?;
                                // A weird exception for obj_id location .. usually in context info, but in wave if for this unique case
                                let peer_cid = header.session_cid.get();
                                //let mut state_container = session.state_container.borrow_mut();
                                let object_id = header.wave_id.get();
                                let group_id = header.group.get();
                                if !state_container.on_group_header_ack_received(object_id, peer_cid,group_id, initial_wave_window, to_primary_stream) {
                                    if !tcp_only {
                                        PrimaryProcessorResult::EndSession("UDP sockets disconnected")
                                    } else {
                                        PrimaryProcessorResult::EndSession("TCP sockets disconnected")
                                    }
                                } else {
                                    PrimaryProcessorResult::Void
                                }
                            }

                            Some((false, _, message_opt)) => {
                                // valid but not ready to accept.
                                // Possible reasons: too large, target not valid (e.g., not registered, not connected, etc)
                                let ticket = header.context_info.get();
                                log::info!("Header ACK was valid, but the receiving end is not receiving the packet at this time. Clearing local memory ...");
                                //let mut state_container = session.state_container.borrow_mut();
                                let group = header.group.get();
                                let key = GroupKey::new(header.session_cid.get(), group);
                                if let None = state_container.outbound_transmitters.remove(&key) {
                                    log::error!("Unable to remove outbound transmitter for group {} (non-existent)", group);
                                }
                                std::mem::drop(state_container);

                                session.send_to_kernel(HdpServerResult::OutboundRequestRejected(ticket.into(), message_opt));
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
                                match state_container.on_window_tail_received(&pqc,state_container_ref, &header, &drill, waves_in_window, &session.time_tracker, to_primary_stream) {
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
                        match validation::group::validate_wave_do_retransmission( &payload) {
                            Ok(_) => {
                                // The internal session timer will handle the outbound dispatch of packets
                                // once
                                state_container.on_wave_do_retransmission_received(&drill, &header, &payload);
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
                            Ok(next_window_opt) => {
                                let tcp_only = session.tcp_only;

                                if next_window_opt.is_some() {
                                    log::info!("WAVE_ACK implies window completion!");
                                }

                                let to_primary_stream = session.to_primary_stream.as_ref()?;
                                // the window is done. Since this node is the transmitter, we then make a call to begin sending the next wave
                                if !state_container.on_wave_ack_received(drill.get_cid(), &header, tcp_only, next_window_opt, to_primary_stream) {
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

                            Err(err) => {
                                trace!("Error validating WAVE_ACK: {}", err.to_string());
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
                        session.send_to_kernel(HdpServerResult::DataDelivery(ticket, implicated_cid, reconstructed_packet));
                        PrimaryProcessorResult::Void
                    }
                }

                res => res.into()
            }
    }
}

pub(super) fn get_proper_pqc_and_drill<K: ExpectedInnerTargetMut<StateContainerInner>>(header_drill_vers: u32, sess_cnac: &ClientNetworkAccount, sess_pqc: &Arc<PostQuantumContainer>, state_container: &InnerParameterMut<K, StateContainerInner>, proxy_cid_info: Option<(u64, u64)>) -> Option<(Arc<PostQuantumContainer>, Drill)> {
    if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
        // since this conn was proxied, we need to go into the virtual conn layer to get the peer session crypto. HOWEVER:
        // In the case that a packet is proxied back to the source, the adjacent endpoint inscribes this node's cid
        // inside the target_cid (that way the packet routes correctly to this node). However, this is problematic here
        // since we use the original implica
        if let Some(vconn) = state_container.active_virtual_connections.get(&original_implicated_cid) {
            if let Some(endpoint_container) = vconn.endpoint_container.as_ref() {
                let drill = endpoint_container.endpoint_crypto.get_drill(Some(header_drill_vers))?.clone();
                let pqc = endpoint_container.endpoint_crypto.pqc.clone();
                Some((pqc, drill))
            } else {
                log::error!("Unable to find endpoint container for vconn {}", &vconn.connection_type);
                return None
            }
        } else {
            log::error!("Unable to find vconn for {}. Unable to process primary group packet", original_implicated_cid);
            return None
        }
    } else {
        // since this was not proxied, use the ordinary pqc and drill

        let drill = sess_cnac.get_drill(Some(header_drill_vers))?;
        Some((sess_pqc.clone(), drill))
    }
}