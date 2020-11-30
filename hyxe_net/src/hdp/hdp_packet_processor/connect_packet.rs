use super::includes::*;
use crate::hdp::state_container::VirtualConnectionType;
use std::sync::Arc;
use atomic::Ordering;

/// This will optionally return an HdpPacket as a response if deemed necessary
#[inline]
pub fn process(session: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session);

    if !session.is_provisional() {
        log::error!("Connect packet received, but the system is not in a provisional state. Dropping");
        return PrimaryProcessorResult::Void;
    }

    if !inner!(session.state_container).pre_connect_state.success {
        log::error!("Connect packet received, but the system has not yet completed the pre-connect stage. Dropping");
        return PrimaryProcessorResult::Void;
    }

    // the preconnect stage loads the CNAC for us. However, only Alice has her PQC by the time a packet
    // is received here, and as such, only validate non-stage0 connect packets
    let (header, payload) = packet.parse()?;
    let cnac = session.cnac.as_ref()?;

    match header.cmd_aux {
        // Node is Bob. A connection request has been sent inbound. Every stage after 0 implicates the existence of a PQC
        packet_flags::cmd::aux::do_connect::STAGE0 => {
            log::info!("STAGE 0 CONNECT PACKET");
            let last_stage = inner!(session.state_container).connect_state.last_stage;
            if last_stage == packet_flags::cmd::aux::do_connect::STAGE0 {
                match validation::do_connect::validate_stage0_packet(cnac, &header, payload) {
                    Some((drill_required, bob_pqc)) => {
                        let ciphertext = bob_pqc.get_ciphertext()?;

                        let (nonce, stage1_packet) = hdp_packet_crafter::do_connect::craft_stage1_packet(&drill_required, header.algorithm, ciphertext, session.time_tracker.get_global_time_ns());
                        // store the drill and nonce in the stage container
                        //log::info!("Generated login nonce: {:?}", &nonce);
                        //let post_quantum_container = cnac.get_post_quantum_container().await?;
                        let mut state_container = inner_mut!(session.state_container);
                        // This won't get loaded into session.pqc until later
                        //state_container.connect_stage.generated_pqc = Some(bob_pqc);
                        state_container.connect_register_drill = Some(drill_required);
                        state_container.connect_state.nonce = Some(nonce);
                        state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
                        state_container.connect_state.on_connect_packet_received();
                        std::mem::drop(state_container);

                        // now, both sides have a pqc loaded. HOWEVER, the ciphertext needs to be registered on Alice's end
                        // before using the pqc for coms
                        session.post_quantum = Some(Arc::new(bob_pqc));
                        session.state = SessionState::ConnectionProcess;
                        PrimaryProcessorResult::ReplyToSender(stage1_packet)
                    }

                    None => {
                        log::error!("Validating stage 0 packet failed!");
                        session.state = SessionState::NeedsConnect;
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let mut state_container = inner_mut!(session.state_container);
                        state_container.connect_state.on_fail(timestamp);
                        state_container.connect_state.on_connect_packet_received();
                        PrimaryProcessorResult::Void
                    }
                }
            } else {
                warn!("A stage 1 packet was received, but the last stage was not 0. Dropping packet");
                PrimaryProcessorResult::Void
            }
        }

        // Node is Alice. This packet will contain the nonce. The nonce gets added to the [StageContainer] by the validation fn
        packet_flags::cmd::aux::do_connect::STAGE1 => {
            log::info!("STAGE 1 CONNECT PACKET");
            let mut state_container = inner_mut!(session.state_container);
            if state_container.connect_state.last_stage == packet_flags::cmd::aux::do_connect::STAGE0 {
                if let Some(ref _cnac) = session.cnac.clone() {
                    let drill_required = state_container.connect_register_drill.clone()?;
                    let proposed_credentials = state_container.connect_state.proposed_credentials.take()?;
                    let timestamp = session.time_tracker.get_global_time_ns();
                    match validation::do_connect::validate_stage1_packet(&drill_required, &header, &*payload) {
                        Some((decrypted_nonce, decrypted_ciphertext)) => {
                            // take the pqc, update the internals to get the symmetric key
                            let mut pqc = state_container.connect_state.pqc.take()?;
                            //let post_quantum = state_container.connect_stage.generated_pqc.as_mut()?;
                            match pqc.alice_on_receive_ciphertext(decrypted_ciphertext.as_ref()) {
                                Ok(_) => {
                                    let stage2_packet = hdp_packet_crafter::do_connect::craft_stage2_packet(proposed_credentials, &pqc,&drill_required, timestamp);
                                    //let mut state_container = session.state_container.borrow_mut();
                                    state_container.connect_register_drill = Some(drill_required);
                                    state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
                                    state_container.connect_state.nonce = Some(decrypted_nonce);
                                    state_container.connect_state.on_connect_packet_received();
                                    std::mem::drop(state_container);
                                    session.post_quantum = Some(Arc::new(pqc));

                                    PrimaryProcessorResult::ReplyToSender(stage2_packet)
                                }

                                Err(_) => {
                                    log::error!("Unable to process ciphertext");
                                    PrimaryProcessorResult::Void
                                }
                            }
                        }

                        None => {
                            log::error!("Validating stage 1 packet failed");
                            let timestamp = session.time_tracker.get_global_time_ns();
                            state_container.connect_state.on_fail(timestamp);
                            state_container.connect_state.on_connect_packet_received();
                            std::mem::drop(state_container);
                            session.state = SessionState::NeedsConnect;
                            PrimaryProcessorResult::Void
                        }
                    }
                } else {
                    warn!("A stage 1 packet was received, and the last stage was 0, but nevertheless the CNAC does not exist");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("A stage 1 packet was received, but the last stage was not 0. Dropping packet");
                PrimaryProcessorResult::Void
            }
        }

        // since every stage after the prior implicates the existence of a PQC, get begin validation
        stage => {
            log::info!("RECV nonzero stage CONNECT packet");
            let ref pqc = session.post_quantum.clone()?;
            let (header, payload, _, _) = packet.decompose();
            let (header, payload, _drill) = validation::aead::validate(cnac, pqc, &header, payload)?;

            match stage {

                // Node is Bob. Bob gets the encrypted username and password (separately encrypted)
                packet_flags::cmd::aux::do_connect::STAGE2 => {
                    log::info!("STAGE 2 CONNECT PACKET");
                    let state_container = inner!(session.state_container);
                    if state_container.connect_state.last_stage == packet_flags::cmd::aux::do_connect::STAGE1 {
                        let drill = state_container.connect_register_drill.clone()?;
                        let cid = drill.get_cid();
                        match validation::do_connect::validate_stage2_packet(cnac, &header, &*payload) {
                            Ok(_) => {
                                std::mem::drop(state_container);
                                let success_time = session.time_tracker.get_global_time_ns();
                                let addr = session.remote_peer.clone();
                                let is_personal = !session.is_server;
                                let kernel_ticket =  session.kernel_ticket.clone();


                                let mut state_container = inner_mut!(session.state_container);

                                // transmit peers to synchronize
                                let peers = cnac.get_hyperlan_peer_list().unwrap_or(Vec::with_capacity(0));
                                //let pqc = state_container.connect_stage.generated_pqc.take();
                                state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::SUCCESS;
                                state_container.connect_state.success_time = Some(success_time);
                                state_container.connect_state.fail_time = None;
                                state_container.connect_state.on_connect_packet_received();
                                state_container.cnac = Some(cnac.clone());

                                std::mem::drop(state_container);

                                // Upgrade the connect BEFORE updating the CNAC
                                if !session.session_manager.upgrade_connection(addr, cid) {
                                    return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection")
                                }

                                //cnac.update_post_quantum_container(post_quantum).await?;
                                //cnac.spawn_save_task_on_threadpool();
                                // register w/ peer layer, get mail in the process
                                let mailbox_items = session.session_manager.register_session_with_peer_layer(cid);
                                let success_packet = hdp_packet_crafter::do_connect::craft_final_status_packet(true, mailbox_items,session.create_welcome_message(cid), peers, &drill, pqc,success_time);

                                session.implicated_cid.store(Some(cid), Ordering::SeqCst);
                                session.state = SessionState::Connected;

                                let cxn_type = VirtualConnectionType::HyperLANPeerToHyperLANServer(cid);
                                session.send_to_kernel(HdpServerResult::ConnectSuccess(kernel_ticket, cid, addr, is_personal, cxn_type, format!("Client {} successfully established a connection to the local HyperNode", cid)))?;

                                PrimaryProcessorResult::ReplyToSender(success_packet)
                            }

                            Err(err) => {
                                log::error!("Error validating stage2 packet. Reason: {}", err.to_string());
                                std::mem::drop(state_container);
                                let fail_time = session.time_tracker.get_global_time_ns();
                                session.state = SessionState::NeedsConnect;
                                let mut state_container = inner_mut!(session.state_container);
                                state_container.connect_state.on_fail(fail_time);
                                state_container.connect_state.on_connect_packet_received();

                                let result = if let Some(ref drill) = state_container.connect_register_drill.clone() {
                                    PrimaryProcessorResult::ReplyToSender(hdp_packet_crafter::do_connect::craft_final_status_packet(false, None,err.to_string(), Vec::with_capacity(0), drill, pqc,fail_time))
                                } else {
                                    log::warn!("Unable to get connect stage drill, even though it was expected by stage 2.");
                                    PrimaryProcessorResult::Void
                                };
                                state_container.connect_register_drill = None;

                                result
                            }
                        }
                    } else {
                        log::warn!("A stage 2 packet was received, but the last stage was not 1. Dropping packet");
                        PrimaryProcessorResult::Void
                    }
                }

                packet_flags::cmd::aux::do_connect::FAILURE => {
                    log::info!("STAGE FAILURE CONNECT PACKET");
                    let current_time = session.time_tracker.get_global_time_ns();
                    let kernel_ticket = session.kernel_ticket.clone();

                    let mut state_container = inner_mut!(session.state_container);
                    if let Ok(Some((drill, message, _, _))) = validation::do_connect::validate_final_status_packet(&mut wrap_inner_mut!(state_container), &header, &*payload) {
                        let message = String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string());
                        log::info!("The server refused to login the user. Reason: {}", &message);
                        let cid = drill.get_cid();
                        state_container.connect_state.on_fail(current_time);
                        state_container.connect_state.on_connect_packet_received();
                        std::mem::drop(state_container);

                        //session.session_manager.clear_provisional_tracker(session.kernel_ticket);

                        session.implicated_cid.store(None, Ordering::SeqCst);
                        session.state = SessionState::NeedsConnect;
                        session.needs_close_message.store(false, Ordering::SeqCst);
                        session.send_to_kernel(HdpServerResult::ConnectFail(kernel_ticket, Some(cid), message))?;
                        PrimaryProcessorResult::EndSession("Failed connecting. Retry again")
                    } else {
                        trace!("An invalid FAILURE packet was received; dropping due to invalid signature");
                        PrimaryProcessorResult::Void
                    }
                }

                // Node is finally Alice. The login either failed or succeeded
                packet_flags::cmd::aux::do_connect::SUCCESS => {
                    log::info!("STAGE SUCCESS CONNECT PACKET");
                    let mut state_container = inner_mut!(session.state_container);
                    let last_stage = state_container.connect_state.last_stage;

                    if last_stage == packet_flags::cmd::aux::do_connect::STAGE1 {
                        if let Ok(Some((drill, message, mailbox_items, peers))) = validation::do_connect::validate_final_status_packet(&mut wrap_inner_mut!(state_container), &header, &*payload) {
                            let message = String::from_utf8(message).unwrap_or(String::from("Invalid message"));
                            let current_time = session.time_tracker.get_global_time_ns();
                            let kernel_ticket = session.kernel_ticket;
                            let cid = drill.get_cid();

                            log::info!("The login to the server was a success. Welcome Message: {}", &message);
                            state_container.connect_state.on_success(current_time);
                            state_container.connect_state.on_connect_packet_received();
                            // now that we are done with the PQC, we can insert it where with an rc into the session
                            state_container.cnac = Some(cnac.clone());

                            std::mem::drop(state_container);

                            cnac.synchronize_hyperlan_peer_list(&peers);
                            session.implicated_cid.store(Some(cid), Ordering::SeqCst); // This makes is_provisional equal to false
                            session.state = SessionState::Connected;

                            let addr = session.remote_peer.clone();
                            let is_personal = !session.is_server;

                            // Upgrade the connect BEFORE updating the CNAC
                            if !session.session_manager.upgrade_connection(session.remote_peer.clone(), cid) {
                                return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection")
                            }

                            // synchronize the cnac
                            //cnac.update_post_quantum_container(pqc).await?;
                            //cnac.spawn_save_task_on_threadpool();

                            //session.post_quantum = pqc;
                            let cxn_type = VirtualConnectionType::HyperLANPeerToHyperLANServer(cid);
                            session.send_to_kernel(HdpServerResult::ConnectSuccess(kernel_ticket, cid, addr, is_personal, cxn_type, message))?;

                            // Now, send keep alives!
                            let timestamp = session.time_tracker.get_global_time_ns();

                            //session.needs_close_message = false;

                            //finally, if there are any mailbox items, send them to the kernel for processing
                            if let Some(mailbox_delivery) = mailbox_items {
                                session.send_to_kernel(HdpServerResult::MailboxDelivery(cid, None, mailbox_delivery))?;
                            }
                            //session.session_manager.clear_provisional_tracker(session.kernel_ticket);

                            let ka = hdp_packet_crafter::keep_alive::craft_keep_alive_packet(&drill, pqc, timestamp);
                            //session.post_quantum = Some(Arc::new(pqc));
                            PrimaryProcessorResult::ReplyToSender(ka)
                            //PrimaryProcessorResult::Void
                        } else {
                            trace!("An invalid SUCCESS packet was received; dropping due to invalid signature");
                            PrimaryProcessorResult::Void
                        }
                    } else {
                        trace!("An invalid SUCCESS packet was received; dropping since the last local stage was not stage 1");
                        PrimaryProcessorResult::Void
                    }
                }

                n => {
                    trace!("Invalid auxiliary command: {}", n);
                    PrimaryProcessorResult::Void
                }
            }
        }
    }
}