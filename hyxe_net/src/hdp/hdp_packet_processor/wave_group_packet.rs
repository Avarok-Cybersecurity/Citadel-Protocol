use crate::hdp::hdp_packet_processor::primary_group_packet::get_proper_pqc_and_drill;
use crate::hdp::hdp_server::HdpServerRequest;

use super::includes::*;
use atomic::Ordering;

/// This will handle an inbound group packet
pub fn process<K: ExpectedInnerTargetMut<HdpSessionInner>>(session: &mut InnerParameterMut<K, HdpSessionInner>, v_src_port: u16, v_local_port: u16, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8], proxy_cid_info: Option<(u64, u64)>) -> GroupProcessorResult {
    debug_assert_eq!(packet_flags::cmd::primary::GROUP_PACKET, header.cmd_primary);

    if let Some(sess_cnac) = session.cnac.as_ref() {
        match header.cmd_aux {
            packet_flags::cmd::aux::group::GROUP_PAYLOAD => {
                //log::info!("GROUP PAYLOAD RECEIVED");
                // we need to get the pqc and drill for the appropriate type.

                //let local_multiport_start = session.local_multiport_start;
                //let remote_multiport_start = session.remote_peer_multiport_start;
                let to_primary_stream = session.to_primary_stream.as_ref()?;
                let sess_pqc = session.post_quantum.as_ref()?;
                let session_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                let mut state_container = inner_mut!(session.state_container);

                let (pqc, drill) = get_proper_pqc_and_drill(header.drill_version.get(), sess_cnac, sess_pqc, &wrap_inner_mut!(state_container), proxy_cid_info)?;

                //let mut state_container = session.state_container.borrow_mut();
                match state_container.on_group_payload_packet_received(v_src_port, v_local_port, &pqc, header, payload, &session.time_tracker, to_primary_stream, &drill) {
                    Ok(Some((ticket, virtual_target, security_level, reconstructed_packet))) => {
                        // Now, we need to determine the next send location for this RECONSTRUCTED packet.
                        // if the target cid equals the CID of this connection, it means the packet is at its destination
                        match virtual_target {
                            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                if target_cid != session_cid {
                                    // Now, make sure the target_cid is connected to the client in virtual connection table
                                    if state_container.active_virtual_connections.contains_key(&target_cid) {
                                        // GOOD. Now, we can reroute the packet
                                        // NOTE: This form of routing is less efficient than proxying with a nonzero target_cid in the packet headers.
                                        // However, it ensures that a packet's trajectory cannot be discerned, thus hiding a "who" in the conversation
                                        let reroute_request = HdpServerRequest::SendMessage(reconstructed_packet, target_cid, virtual_target, security_level);
                                        let _ = session.session_manager.send_local_server_request(Some(ticket), reroute_request);
                                        GroupProcessorResult::Void
                                    } else {
                                        // This means that the target client disconnected in the middle of the transfer
                                        // send error packet with same ticket provided. ASSUME disconnect mechanism handles sending of packet
                                        log::error!("Peer {} disconnected during the transmission of group {}", target_cid, header.group.get());
                                        GroupProcessorResult::Void
                                    }
                                } else {
                                    // if the target cid is this sessions, it means the packet has arrived.
                                    // We need to route the packet to the channel
                                    //GroupProcessorResult::SendToKernel(ticket, reconstructed_packet)
                                    if !state_container.forward_data_to_channel_as_endpoint(implicated_cid, reconstructed_packet) {
                                        log::error!("Unable to forward data to local channel");
                                    }
                                    GroupProcessorResult::Void
                                }
                            }

                            VirtualConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                                // Whether the current node is the peer or server, one hop is all that's needed
                                GroupProcessorResult::SendToKernel(ticket, reconstructed_packet)
                            }

                            _ => {
                                unimplemented!("HyperWAN functionality not yet implemented")
                            }
                        }
                    }

                    Err(err) => {
                        trace!("An error occurred while rendering group payload packet: {}", err.to_string());
                        GroupProcessorResult::Void
                    }

                    _ => {
                        GroupProcessorResult::Void
                    }
                }
            }

            _ => {
                trace!("Invalid GROUP auxiliary command inscribed on inbound packet");
                GroupProcessorResult::Void
            }
        }
    } else {
        trace!("Invalid load state. CNAC is missing");
        GroupProcessorResult::Void
    }
}
