use atomic::Ordering;

use super::includes::*;

/// processes a deregister packet. The client must be connected to the HyperLAN Server in order to DeRegister
#[inline]
pub fn process(session_main: &HdpSession, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> PrimaryProcessorResult {
    debug_assert_eq!(header.cmd_primary, packet_flags::cmd::primary::DO_DEREGISTER);
    let mut session = inner_mut!(session_main);

    if session.state != SessionState::Connected {
        log::error!("disconnect packet received, but session state is not connected. Must be connected to deregister. Dropping");
        return PrimaryProcessorResult::Void;
    }

    if session.post_quantum.is_none() {
        log::error!("Post quantum container not set");
        return PrimaryProcessorResult::Void;
    }

    let post_quantum = session.post_quantum.as_ref()?;
    let timestamp = session.time_tracker.get_global_time_ns();
    if let Some(cnac) = session.cnac.as_ref() {
        let mut state_container = inner_mut!(session.state_container);
        match header.cmd_aux {
            packet_flags::cmd::aux::do_deregister::STAGE0 => {
                log::info!("STAGE 0 DEREGISTER PACKET RECV");
                if !state_container.deregister_state.in_progress && state_container.deregister_state.last_stage == packet_flags::cmd::aux::do_deregister::STAGE0 {
                    if let Some((virtual_connection_type, drill)) = validation::do_deregister::validate_stage0(cnac, header, payload) {
                        let nonce = drill.get_random_aes_gcm_nonce();
                        let stage1_packet = hdp_packet_crafter::do_deregister::craft_stage1(&drill, &nonce, timestamp);

                        state_container.deregister_state.in_progress = true;
                        state_container.deregister_state.last_stage = packet_flags::cmd::aux::do_deregister::STAGE1;
                        state_container.deregister_state.nonce = Some(nonce);
                        state_container.deregister_state.virtual_connection_type = Some(virtual_connection_type);
                        state_container.deregister_state.on_packet_received(timestamp);
                        PrimaryProcessorResult::ReplyToSender(stage1_packet)
                    } else {
                        log::error!("Unable to validate stage 0 packet. Dropping");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("State not in progress or stage stage not 0. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_deregister::STAGE1 => {
                log::info!("STAGE 1 DEREGISTER PACKET RECV");
                if state_container.deregister_state.last_stage == packet_flags::cmd::aux::do_deregister::STAGE0 {
                    if let Some((nonce, drill)) = validation::do_deregister::validate_stage1(cnac, header, payload) {
                        let stage2_packet = hdp_packet_crafter::do_deregister::craft_stage2(&drill, post_quantum, &nonce, timestamp);
                        state_container.deregister_state.nonce = Some(nonce);
                        state_container.deregister_state.last_stage = packet_flags::cmd::aux::do_deregister::STAGE2;
                        state_container.deregister_state.on_packet_received(timestamp);

                        PrimaryProcessorResult::ReplyToSender(stage2_packet)
                    } else {
                        log::error!("Unable to validate stage 1 packet. Dropping");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Received a stage 1 packet, but previous stage not 0. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_deregister::STAGE2 => {
                log::info!("STAGE 2 DEREGISTER PACKET RECV");
                if state_container.deregister_state.last_stage == packet_flags::cmd::aux::do_deregister::STAGE1 {
                    let nonce = state_container.deregister_state.nonce.as_ref()?;
                    if let Some(ref drill) = validation::do_deregister::validate_stage2(cnac, header, nonce, post_quantum, payload) {
                        let virtual_connection_type = state_container.deregister_state.virtual_connection_type.clone()?;
                        let cnac= cnac.clone();
                        std::mem::drop(state_container);

                        match virtual_connection_type {
                            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                deregister_from_hyperlan_peer(implicated_cid, target_cid, wrap_inner_mut!(session), cnac, drill, timestamp)
                            }

                            VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid)  => {
                                deregister_from_hyperlan_server(implicated_cid, wrap_inner_mut!(session), drill, timestamp)
                            }

                            VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                                // TODO: HyperWAN functionality
                                unimplemented!()
                            }

                            VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                                // TODO: HyperWAN functionality
                                unimplemented!()
                            }
                        }
                    } else {
                        log::error!("Unable to validate stage 1 packet. Sending failure packet");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Received a stage 2 packet, but previous stage not 1. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_deregister::SUCCESS => {
                if state_container.deregister_state.last_stage == packet_flags::cmd::aux::do_deregister::STAGE2 {
                    if let Some(true) = validation::do_deregister::validate_stage_final(cnac, header, payload) {
                        let cnac = cnac.clone();
                        let virt_cxn_type = state_container.deregister_state.virtual_connection_type.clone()?;
                        let _ticket = state_container.deregister_state.current_ticket;
                        std::mem::drop(state_container);

                        match virt_cxn_type {
                            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                deregister_from_hyperlan_peer_as_client(implicated_cid, target_cid, wrap_inner_mut!(session), cnac)
                            }

                            VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid)  => {
                                deregister_from_hyperlan_server_as_client(implicated_cid, wrap_inner_mut!(session))
                            }

                            VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                                // TODO: HyperWAN functionality
                                unimplemented!()
                            }

                            VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                                // TODO: HyperWAN functionality
                                unimplemented!()
                            }
                        }
                    } else {
                        log::error!("Unable to validate stage SUCCESS packet");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Received a stage SUCCESS packet, but previous stage not 2. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            packet_flags::cmd::aux::do_deregister::FAILURE => {
                if state_container.deregister_state.last_stage == packet_flags::cmd::aux::do_deregister::STAGE2 {
                    if let Some(false) = validation::do_deregister::validate_stage_final(cnac, header, payload) {
                        let ticket = state_container.deregister_state.current_ticket.clone();
                        state_container.deregister_state.on_fail();
                        std::mem::drop(state_container);
                        let cid = session.implicated_cid.load(Ordering::Relaxed)?;
                        session.kernel_tx.send(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(cid), ticket, true, false))?;
                        log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", cid);
                        PrimaryProcessorResult::EndSession("Deregistration failure. Closing connection anyways")
                    } else {
                        log::error!("Unable to validate stage FAILURE packet");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Received a stage FAILURE packet, but previous stage not 2. Dropping");
                    PrimaryProcessorResult::Void
                }
            }

            _ => {
                log::error!("Invalid auxiliary command");
                PrimaryProcessorResult::Void
            }
        }
    } else {
        log::error!("Missing CNAC from session");
        PrimaryProcessorResult::Void
    }
}

fn deregister_from_hyperlan_server<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, mut session: InnerParameterMut<K, HdpSessionInner>, drill: &Drill, timestamp: i64) -> PrimaryProcessorResult {
    let mut state_container = inner_mut!(session.state_container);
    let ticket = state_container.deregister_state.current_ticket;

    // Reset the internal state to allow other processes to run
    state_container.deregister_state.on_success();
    //let target_cid = state_container.deregister_state.target_cid;
    std::mem::drop(state_container);
    let acc_manager = session.account_manager.clone();

    let (ret, success) = if acc_manager.delete_client_by_cid(implicated_cid) {
        log::info!("Successfully purged account {} locally!", implicated_cid);
        let stage_success_packet = hdp_packet_crafter::do_deregister::craft_final(drill, true, timestamp);
        // At the end of the deregistration phase, the session also ends
        (PrimaryProcessorResult::ReplyToSender(stage_success_packet), true)
    } else {
        log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", implicated_cid);
        let stage_failure_packet = hdp_packet_crafter::do_deregister::craft_final(drill, false, timestamp);
        (PrimaryProcessorResult::ReplyToSender(stage_failure_packet), false)
    };

    // This ensures no further packets are processed
    session.state = SessionState::NeedsRegister;
    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), ticket, false, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}

#[allow(unused_results)]
fn deregister_from_hyperlan_peer<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, target_cid: u64, mut session: InnerParameterMut<K, HdpSessionInner>, cnac: ClientNetworkAccount, drill: &Drill, timestamp: i64) -> PrimaryProcessorResult {
    // Whereas below wherein we remove this session's CNAC from the server,
    // in this case, we only remove the mutually-agreed entry in this CNAC instead.
    // We also remove any active virtual connection to the target cid
    let mut state_container = inner_mut!(session.state_container);
    let ticket = state_container.deregister_state.current_ticket;
    state_container.deregister_state.on_success();
    // Remove the active virtual connection to prevent any further pending transactions
    state_container.active_virtual_connections.remove(&target_cid);
    std::mem::drop(state_container);
    // This ensures no further packets are processed server-side
    // Now, we need to target the CNAC's mutual's list
    // pub async fn delete_mutual_peer(&self, cid: u64, parent_icid: Option<u64>) -> bool
    let (ret, success) = if cnac.remove_hyperlan_peer(target_cid).is_some() {
        log::info!("SUCCESS deleting mutual HyperLAN peer {} from CNAC {}", target_cid, cnac.get_id());
        let stage_success_packet = hdp_packet_crafter::do_deregister::craft_final(drill, true, timestamp);
        // At the end of the deregistration phase, the session also ends
        (PrimaryProcessorResult::ReplyToSender(stage_success_packet), true)
    } else {
        log::info!("ERROR deleting mutual HyperLAN peer {} from CNAC {}", target_cid, cnac.get_id());
        let stage_failure_packet = hdp_packet_crafter::do_deregister::craft_final(drill, false, timestamp);
        (PrimaryProcessorResult::ReplyToSender(stage_failure_packet), false)
    };

    session.state = SessionState::NeedsRegister;
    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid), ticket, false, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}

fn deregister_from_hyperlan_server_as_client<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, session: InnerParameterMut<K, HdpSessionInner>) -> PrimaryProcessorResult {
    let mut state_container = inner_mut!(session.state_container);

    let ticket = state_container.deregister_state.current_ticket.clone();
    state_container.deregister_state.on_success();
    std::mem::drop(state_container);
    let acc_manager = session.account_manager.clone();

    let (ret, success) = if acc_manager.delete_client_by_cid(implicated_cid) {
        log::info!("Successfully purged account {} locally!", implicated_cid);

        (PrimaryProcessorResult::EndSession("Session ended after successful deregistration!"), true)
    } else {
        log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", implicated_cid);
        (PrimaryProcessorResult::EndSession("Session ended after unsuccessful deregistration"), false)
    };

    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), ticket, true, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}

/// We only need to delete the client from the CNAC, as well as any active virtual connections to the target cid
#[allow(unused_results)]
fn deregister_from_hyperlan_peer_as_client<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, target_cid: u64, session: InnerParameterMut<K, HdpSessionInner>, cnac: ClientNetworkAccount) -> PrimaryProcessorResult {
    let mut state_container = inner_mut!(session.state_container);

    let ticket = state_container.deregister_state.current_ticket.clone();
    state_container.deregister_state.on_success();
    // Remove virtual connection, if existent
    state_container.active_virtual_connections.remove(&target_cid);
    std::mem::drop(state_container);

    let (ret, success) = if cnac.remove_hyperlan_peer(target_cid).is_some() {
        log::info!("SUCCESS deleting mutual HyperLAN peer {} from CNAC {}", target_cid, implicated_cid);
        (PrimaryProcessorResult::EndSession("Session ended after successful deregistration!"), true)
    } else {
        log::info!("FAILURE deleting mutual HyperLAN peer {} from CNAC {}", target_cid, implicated_cid);
        (PrimaryProcessorResult::EndSession("Session ended after unsuccessful deregistration"), false)
    };

    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid), ticket, true, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);
    ret
}