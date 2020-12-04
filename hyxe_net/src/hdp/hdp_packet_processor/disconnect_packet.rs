use atomic::Ordering;

use crate::hdp::state_container::VirtualConnectionType;

use super::includes::*;

/// Stage 0: Alice sends Bob a DO_DISCONNECT request packet
/// Stage 1: Bob sends Alice an encrypted nonce
/// Stage 2: Alice sends Bob an encrypted subdrill as a form of verification
/// Stage 3: Bob sends either a SUCCESS or FAILURE packet
#[inline]
pub fn process(session: &HdpSession, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> PrimaryProcessorResult {
    debug_assert_eq!(header.cmd_primary, packet_flags::cmd::primary::DO_DISCONNECT);
    let session = inner_mut!(session);

    if session.state != SessionState::Connected {
        log::error!("disconnect packet received, but session state is not connected. Dropping");
        return PrimaryProcessorResult::Void;
    }

    if let Some(cnac) = session.cnac.as_ref() {
        let mut state_container = inner_mut!(session.state_container);
        match header.cmd_aux {
            packet_flags::cmd::aux::do_disconnect::STAGE0 => {
                log::info!("STAGE 0 DISCONNECT PACKET RECEIVED");
                if state_container.disconnect_state.last_stage != packet_flags::cmd::aux::do_disconnect::STAGE0 {
                    log::error!("A stage 0 packet was received, but the stage is not zero. Dropping");
                    return PrimaryProcessorResult::Void;
                }

                if let Some((virtual_connection_type, ticket, drill)) = validation::do_disconnect::validate_stage0(cnac, header, payload) {
                    let nonce = drill.get_random_aes_gcm_nonce();
                    state_container.disconnect_state.last_stage = packet_flags::cmd::aux::do_disconnect::STAGE1;
                    state_container.disconnect_state.nonce = Some(nonce.clone());
                    state_container.disconnect_state.virtual_connection_type = Some(virtual_connection_type);
                    state_container.disconnect_state.ticket = ticket;

                    std::mem::drop(state_container);
                    let timestamp = session.time_tracker.get_global_time_ns();

                    let stage1_packet = hdp_packet_crafter::do_disconnect::craft_stage1(&drill, ticket, &nonce, timestamp);
                    PrimaryProcessorResult::ReplyToSender(stage1_packet)
                } else {
                    log::error!("Unable to validate stage 0 packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_disconnect::STAGE1 => {
                log::info!("STAGE 1 DISCONNECT PACKET RECEIVED");
                if state_container.disconnect_state.last_stage != packet_flags::cmd::aux::do_disconnect::STAGE0 {
                    log::error!("A stage 1 packet was received, but the stage is not zero. Dropping");
                    return PrimaryProcessorResult::Void;
                }

                if state_container.disconnect_state.ticket.0 != header.context_info.get() {
                    log::info!("Invalid ticket; dropping");
                    return PrimaryProcessorResult::Void;
                }

                if let Some((nonce, ticket, drill)) = validation::do_disconnect::validate_stage1(cnac, header, payload) {
                    if ticket == state_container.disconnect_state.ticket {
                        // We already have the other values set, except the nonce
                        state_container.disconnect_state.nonce = Some(nonce.clone());
                        state_container.disconnect_state.last_stage = packet_flags::cmd::aux::do_disconnect::STAGE2;
                        std::mem::drop(state_container);
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let post_quantum = session.post_quantum.as_ref()?;
                        let stage2_packet = hdp_packet_crafter::do_disconnect::craft_stage2(&drill, ticket, post_quantum, &nonce, timestamp);
                        PrimaryProcessorResult::ReplyToSender(stage2_packet)
                    } else {
                        log::error!("Invalid ticket on stage 1 disconnect packet. Dropping");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Unable to validate stage 1 packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_disconnect::STAGE2 => {
                log::info!("STAGE 2 DISCONNECT PACKET RECEIVED");
                if state_container.disconnect_state.last_stage != packet_flags::cmd::aux::do_disconnect::STAGE1 {
                    log::error!("A stage 2 packet was received, but the stage is not one. Dropping");
                    return PrimaryProcessorResult::Void;
                }

                if state_container.disconnect_state.ticket.0 != header.context_info.get() {
                    log::info!("Invalid ticket; dropping");
                    return PrimaryProcessorResult::Void;
                }

                let ref nonce = state_container.disconnect_state.nonce.clone()?;
                std::mem::drop(state_container);
                let timestamp = session.time_tracker.get_global_time_ns();
                let post_quantum = session.post_quantum.as_ref()?;

                if let Some((drill, ticket)) = validation::do_disconnect::validate_stage2(cnac, header, nonce, post_quantum, payload) {
                    let mut state_container = inner_mut!(session.state_container);
                    let virt_cxn_type = state_container.disconnect_state.virtual_connection_type.clone()?;
                    state_container.disconnect_state.last_stage = packet_flags::cmd::aux::do_disconnect::SUCCESS;
                    // Now, we have to begin a do_disconnect with the adjacent terminal, or, end the current session
                    match virt_cxn_type {
                        VirtualConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                            let packet = hdp_packet_crafter::do_disconnect::craft_final(true, &drill, ticket, timestamp, "Disconnect success!");
                            std::mem::drop(state_container);
                            session.needs_close_message.store(true, Ordering::SeqCst);
                            PrimaryProcessorResult::ReplyToSender(packet)
                        }

                        VirtualConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => {
                            // In this case, we only need to clear the target_cid from the virtual_connections table
                            if let None = state_container.active_virtual_connections.remove(&target_cid) {
                                // Client didn't exist
                                let msg = format!("Target CID {} is not an active virtual connection; quitting", target_cid);
                                log::error!("{}", &msg);
                                state_container.disconnect_state.reset();
                                let fail_packet = hdp_packet_crafter::do_disconnect::craft_final(false, &drill, ticket, timestamp, &msg);
                                PrimaryProcessorResult::ReplyToSender(fail_packet)
                            } else {
                                let msg = format!("Target CID {} has been cleared; virtual connection successfully closed", target_cid);
                                log::error!("{}", &msg);
                                state_container.disconnect_state.reset();
                                let success_packet = hdp_packet_crafter::do_disconnect::craft_final(true, &drill, ticket, timestamp, &msg);
                                PrimaryProcessorResult::ReplyToSender(success_packet)
                            }
                        }

                        VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }

                        VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }
                    }
                } else {
                    log::error!("Unable to validate stage 2 packet. Returning logout false packet");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_disconnect::SUCCESS => {
                log::info!("STAGE SUCCESS DISCONNECT PACKET RECEIVED");

                if state_container.disconnect_state.last_stage != packet_flags::cmd::aux::do_disconnect::STAGE2 {
                    log::error!("A success packet was received, but the last stage was not stage2");
                    return PrimaryProcessorResult::Void;
                }

                if state_container.disconnect_state.ticket.0 != header.context_info.get() {
                    log::info!("Invalid ticket; dropping");
                    return PrimaryProcessorResult::Void;
                }


                if let Ok((message, ticket)) = validation::do_disconnect::validate_final_packet(cnac, header, payload) {
                    log::info!("Disconnect succeeded!");
                    let virtual_connection_type = state_container.disconnect_state.virtual_connection_type.clone()?;

                    match virtual_connection_type {
                        VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                            // End the session
                            let message = message.unwrap_or("Disconnect from HyperLAN server success".as_bytes().to_vec());
                            state_container.kernel_tx.send(HdpServerResult::Disconnect(ticket, implicated_cid, true, Some(virtual_connection_type), String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string())))?;
                            state_container.disconnect_state.reset();
                            std::mem::drop(state_container);

                            session.needs_close_message.store(false, Ordering::SeqCst);
                            PrimaryProcessorResult::EndSession("Disconnect from HyperLAN success")
                        }

                        VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                            // Tell the kernel, and remove the virtual connection
                            let message = message.unwrap_or("Disconnect from HyperLAN client success".as_bytes().to_vec());
                            state_container.kernel_tx.send(HdpServerResult::Disconnect(ticket, implicated_cid, true, Some(virtual_connection_type), String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string())))?;
                            assert!(state_container.active_virtual_connections.remove(&target_cid).is_some());
                            state_container.disconnect_state.reset();

                            PrimaryProcessorResult::Void
                        }

                        VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }

                        VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }
                    }
                } else {
                    log::error!("Unable to validate final packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_disconnect::FAILURE => {
                log::info!("STAGE FAILURE DISCONNECT PACKET RECEIVED");

                if state_container.disconnect_state.ticket.0 != header.context_info.get() {
                    log::info!("Invalid ticket; dropping");
                    return PrimaryProcessorResult::Void;
                }

                if let Ok((message, ticket)) = validation::do_disconnect::validate_final_packet(cnac, header, payload) {
                    log::info!("Disconnect did NOT succeed");
                    let virtual_connection_type = state_container.disconnect_state.virtual_connection_type.clone()?;

                    match virtual_connection_type {
                        VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                            // End the session
                            let message = message.unwrap_or("Disconnect from HyperLAN server failure".as_bytes().to_vec());
                            state_container.kernel_tx.send(HdpServerResult::Disconnect(ticket, implicated_cid, false, Some(virtual_connection_type), String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string())))?;
                            session.needs_close_message.store(false, Ordering::SeqCst);
                            PrimaryProcessorResult::EndSession("Disconnect from HyperLAN failure. Still shutting down")
                        }

                        VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                            // Tell the kernel, and remove the virtual connection
                            let message = message.unwrap_or("Disconnect from HyperLAN client failure. Still removing connection".as_bytes().to_vec());
                            state_container.kernel_tx.send(HdpServerResult::Disconnect(ticket, implicated_cid, false, Some(virtual_connection_type), String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string())))?;
                            assert!(state_container.active_virtual_connections.remove(&target_cid).is_some());
                            PrimaryProcessorResult::Void
                        }

                         VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }

                        VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                            // TODO: Implement HyperWAN functionality
                            unimplemented!()
                        }
                    }
                } else {
                    log::error!("Unable to validate final packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            _ => {
                log::error!("Invalid aux command on disconnect packet");
                PrimaryProcessorResult::Void
            }
        }
    } else {
        log::error!("CNAC is missing. Dropping packet");
        PrimaryProcessorResult::Void
    }
}