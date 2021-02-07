use super::includes::*;
use crate::hdp::state_container::VirtualConnectionType;
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

    // the preconnect stage loads the CNAC for us, as well as re-negotiating the keys
    let cnac = session.cnac.as_ref()?;
    let (header, payload, _, _) = packet.decompose();
    let (header, payload, hyper_ratchet) = validation::aead::validate(cnac, &header, payload)?;
    let security_level = header.security_level.into();

    match header.cmd_aux {
        // Node is Bob. Bob gets the encrypted username and password (separately encrypted)
        packet_flags::cmd::aux::do_connect::STAGE0 => {
            log::info!("STAGE 2 CONNECT PACKET");
            let mut state_container = inner_mut!(session.state_container);
                match validation::do_connect::validate_stage0_packet(cnac, &header, &*payload) {
                    Ok(_) => {

                        let cid = hyper_ratchet.get_cid();
                        let success_time = session.time_tracker.get_global_time_ns();
                        let addr = session.remote_peer.clone();
                        let is_personal = !session.is_server;
                        let kernel_ticket = session.kernel_ticket.clone();

                        // transmit peers to synchronize
                        let peers = cnac.get_hyperlan_peer_list().unwrap_or(Vec::with_capacity(0));
                        //let pqc = state_container.connect_stage.generated_pqc.take();
                        state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::SUCCESS;
                        state_container.connect_state.success_time = Some(success_time);
                        state_container.connect_state.fail_time = None;
                        state_container.connect_state.on_connect_packet_received();

                        std::mem::drop(state_container);

                        // Upgrade the connect BEFORE updating the CNAC
                        if !session.session_manager.upgrade_connection(addr, cid) {
                            return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection");
                        }

                        //cnac.update_post_quantum_container(post_quantum).await?;
                        //cnac.spawn_save_task_on_threadpool();
                        // register w/ peer layer, get mail in the process
                        let mailbox_items = session.session_manager.register_session_with_peer_layer(cid);
                        let success_packet = hdp_packet_crafter::do_connect::craft_final_status_packet(&hyper_ratchet, true, mailbox_items, session.create_welcome_message(cid), peers,success_time, security_level);

                        session.implicated_cid.store(Some(cid), Ordering::SeqCst);
                        session.state = SessionState::Connected;

                        let cxn_type = VirtualConnectionType::HyperLANPeerToHyperLANServer(cid);
                        session.send_to_kernel(HdpServerResult::ConnectSuccess(kernel_ticket, cid, addr, is_personal, cxn_type, format!("Client {} successfully established a connection to the local HyperNode", cid)))?;

                        PrimaryProcessorResult::ReplyToSender(success_packet)
                    }

                    Err(err) => {
                        log::error!("Error validating stage2 packet. Reason: {}", err.to_string());
                        let fail_time = session.time_tracker.get_global_time_ns();
                        state_container.connect_state.on_fail(fail_time);
                        state_container.connect_state.on_connect_packet_received();
                        std::mem::drop(state_container);

                        session.state = SessionState::NeedsConnect;
                        let packet = hdp_packet_crafter::do_connect::craft_final_status_packet(&hyper_ratchet, false, None, err.to_string(), Vec::with_capacity(0),fail_time, security_level);
                        PrimaryProcessorResult::ReplyToSender(packet)
                    }
                }
        }

        packet_flags::cmd::aux::do_connect::FAILURE => {
            log::info!("STAGE FAILURE CONNECT PACKET");
            let current_time = session.time_tracker.get_global_time_ns();
            let kernel_ticket = session.kernel_ticket.clone();

            let mut state_container = inner_mut!(session.state_container);
            if let Ok(Some((message, _, _))) = validation::do_connect::validate_final_status_packet(&header, &*payload) {
                let message = String::from_utf8(message).unwrap_or("Invalid UTF-8 message".to_string());
                log::info!("The server refused to login the user. Reason: {}", &message);
                let cid = hyper_ratchet.get_cid();
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
                if let Ok(Some((message, mailbox_items, peers))) = validation::do_connect::validate_final_status_packet(&header, &*payload) {
                    let message = String::from_utf8(message).unwrap_or(String::from("Invalid message"));
                    let current_time = session.time_tracker.get_global_time_ns();
                    let kernel_ticket = session.kernel_ticket;
                    let cid = hyper_ratchet.get_cid();

                    log::info!("The login to the server was a success. Welcome Message: {}", &message);
                    state_container.connect_state.on_success(current_time);
                    state_container.connect_state.on_connect_packet_received();

                    let use_ka = state_container.keep_alive_timeout_ns != 0;
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
                        return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection");
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

                    if use_ka {
                        let ka = hdp_packet_crafter::keep_alive::craft_keep_alive_packet(&hyper_ratchet, timestamp, security_level);
                        //session.post_quantum = Some(Arc::new(pqc));
                        PrimaryProcessorResult::ReplyToSender(ka)
                    } else {
                        log::warn!("Keep-alive subsystem will not be used for this session as requested");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("An invalid SUCCESS packet was received; dropping due to invalid signature");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("An invalid SUCCESS packet was received; dropping since the last local stage was not stage 1");
                PrimaryProcessorResult::Void
            }
        }

        n => {
            log::error!("Invalid auxiliary command: {}", n);
            PrimaryProcessorResult::Void
        }
    }
}