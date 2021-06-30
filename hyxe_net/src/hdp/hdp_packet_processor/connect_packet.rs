use super::includes::*;
use crate::hdp::state_container::VirtualConnectionType;
use hyxe_crypt::fcm::keys::FcmKeys;
use crate::hdp::hdp_server::ConnectMode;
use hyxe_user::backend::PersistenceHandler;
use crate::error::NetworkError;
use hyxe_user::external_services::PostLoginObject;
use hyxe_user::external_services::rtdb::RtdbClientConfig;
use hyxe_user::re_imports::FirebaseRTDB;

/// This will optionally return an HdpPacket as a response if deemed necessary
#[inline]
pub async fn process(sess_ref: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = sess_ref;

    if !session.is_provisional() {
        log::error!("Connect packet received, but the system is not in a provisional state. Dropping");
        return PrimaryProcessorResult::Void;
    }

    if !inner!(session.state_container).pre_connect_state.success {
        log::error!("Connect packet received, but the system has not yet completed the pre-connect stage. Dropping");
        return PrimaryProcessorResult::Void;
    }

    // the preconnect stage loads the CNAC for us, as well as re-negotiating the keys
    let cnac = return_if_none!(session.cnac.get(), "Unable to load CNAC [connect]");
    let (header, payload, _, _) = packet.decompose();
    let (header, payload, hyper_ratchet) = return_if_none!(validation::aead::validate(&cnac, &header, payload), "Unable to validate connect packet");
    let security_level = header.security_level.into();

    let time_tracker = session.time_tracker.clone();

    match header.cmd_aux {
        // Node is Bob. Bob gets the encrypted username and password (separately encrypted)
        packet_flags::cmd::aux::do_connect::STAGE0 => {
            log::info!("STAGE 2 CONNECT PACKET");
            match validation::do_connect::validate_stage0_packet(&cnac, &*payload).await {
                Ok(fcm_keys) => {
                    let mut state_container = inner_mut!(session.state_container);

                    let cid = hyper_ratchet.get_cid();
                    let success_time = session.time_tracker.get_global_time_ns();
                    let addr = session.remote_peer.clone();
                    let is_personal = !session.is_server;
                    let kernel_ticket = session.kernel_ticket.get();

                    // transmit peers to synchronize


                    //let pqc = state_container.connect_stage.generated_pqc.take();
                    state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::SUCCESS;
                    state_container.connect_state.fail_time = None;
                    state_container.connect_state.on_connect_packet_received();
                    let channel = state_container.init_new_c2s_virtual_connection(&cnac, &mut *inner_mut!(session.updates_in_progress), security_level, kernel_ticket, header.session_cid.get());

                    std::mem::drop(state_container);

                    // Upgrade the connect BEFORE updating the CNAC
                    if !session.session_manager.upgrade_connection(addr, cid) {
                        return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection");
                    }

                    //cnac.update_post_quantum_container(post_quantum).await?;
                    //cnac.spawn_save_task_on_threadpool();
                    // register w/ peer layer, get mail in the process
                    let mailbox_items = session.session_manager.register_session_with_peer_layer(cid);
                    let account_manager = session.account_manager.clone();

                    // Now, we handle the FCM setup
                    let _ = handle_client_fcm_keys(fcm_keys, &cnac, account_manager.get_persistence_handler()).await?;
                    let peers = account_manager.get_persistence_handler().get_hyperlan_peer_list_with_fcm_keys_as_server(cid).await?.unwrap_or(Vec::new());
                    let post_login_object = account_manager.services_handler().on_post_login_serverside(cid).await?;

                    let fcm_packets = cnac.retrieve_raw_fcm_packets().await?;

                    let success_packet = hdp_packet_crafter::do_connect::craft_final_status_packet(&hyper_ratchet, true, mailbox_items, fcm_packets, post_login_object.clone(), session.create_welcome_message(cid), peers, success_time, security_level);

                    session.implicated_cid.set(Some(cid));
                    session.state.set(SessionState::Connected);

                    let cxn_type = VirtualConnectionType::HyperLANPeerToHyperLANServer(cid);
                    session.send_to_kernel(HdpServerResult::ConnectSuccess(kernel_ticket, cid, addr, is_personal, cxn_type, None, post_login_object, format!("Client {} successfully established a connection to the local HyperNode", cid), channel))?;

                    PrimaryProcessorResult::ReplyToSender(success_packet)
                }

                Err(err) => {
                    log::error!("Error validating stage2 packet. Reason: {}", err.to_string());
                    let fail_time = time_tracker.get_global_time_ns();

                    //session.state = SessionState::NeedsConnect;
                    let packet = hdp_packet_crafter::do_connect::craft_final_status_packet(&hyper_ratchet, false, None, None, PostLoginObject::default(), err.to_string(), Vec::new(), fail_time, security_level);
                    PrimaryProcessorResult::ReplyToSender(packet)
                }
            }
        }

        packet_flags::cmd::aux::do_connect::FAILURE => {
            log::info!("STAGE FAILURE CONNECT PACKET");
            let kernel_ticket = session.kernel_ticket.get();

            let mut state_container = inner_mut!(session.state_container);
            if let Some(payload) = validation::do_connect::validate_final_status_packet(&*payload) {
                let message = String::from_utf8(payload.message.to_vec()).unwrap_or("Invalid UTF-8 message".to_string());
                log::info!("The server refused to login the user. Reason: {}", &message);
                let cid = hyper_ratchet.get_cid();
                state_container.connect_state.on_fail();
                std::mem::drop(state_container);

                //session.session_manager.clear_provisional_tracker(session.kernel_ticket);

                session.implicated_cid.set(None);
                session.state.set(SessionState::NeedsConnect);
                session.needs_close_message.set(false);

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
                if let Some(payload) = validation::do_connect::validate_final_status_packet(&*payload) {
                    let cnac = cnac.clone();
                    let message = String::from_utf8(payload.message.to_vec()).unwrap_or(String::from("Invalid message"));
                    let kernel_ticket = session.kernel_ticket.get();
                    let cid = hyper_ratchet.get_cid();

                    log::info!("The login to the server was a success. Welcome Message: {}", &message);
                    state_container.connect_state.on_success();
                    state_container.connect_state.on_connect_packet_received();

                    let use_ka = state_container.keep_alive_timeout_ns != 0;
                    let connect_mode = return_if_none!(state_container.connect_state.connect_mode.clone(), "Unable to load connect mode");
                    let channel = state_container.init_new_c2s_virtual_connection(&cnac,&mut *inner_mut!(session.updates_in_progress), security_level, kernel_ticket, header.session_cid.get());
                    std::mem::drop(state_container);


                    session.implicated_cid.set(Some(cid)); // This makes is_provisional equal to false

                    let addr = session.remote_peer.clone();
                    let is_personal = !session.is_server;

                    // Upgrade the connect BEFORE updating the CNAC
                    if !session.session_manager.upgrade_connection(session.remote_peer.clone(), cid) {
                        return PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection");
                    }

                    let post_login_object = payload.post_login_object.clone();
                    //session.post_quantum = pqc;
                    let cxn_type = VirtualConnectionType::HyperLANPeerToHyperLANServer(cid);
                    session.send_to_kernel(HdpServerResult::ConnectSuccess(kernel_ticket, cid, addr, is_personal, cxn_type, payload.fcm_packets.map(|v| v.into()), payload.post_login_object, message, channel))?;

                    // Now, send keep alives!
                    let timestamp = session.time_tracker.get_global_time_ns();

                    //session.needs_close_message = false;

                    //finally, if there are any mailbox items, send them to the kernel for processing
                    if let Some(mailbox_delivery) = payload.mailbox {
                        session.send_to_kernel(HdpServerResult::MailboxDelivery(cid, None, mailbox_delivery))?;
                    }

                    let persistence_handler = session.account_manager.get_persistence_handler().clone();
                    //session.session_manager.clear_provisional_tracker(session.kernel_ticket);
                    let fcm_keys = session.fcm_keys.clone();
                    session.state.set(SessionState::Connected);

                    // TODO: Clean this up to prevent multiple saves
                    let _ = handle_client_fcm_keys(fcm_keys, &cnac, &persistence_handler).await?;
                    let _ = persistence_handler.synchronize_hyperlan_peer_list_as_client(&cnac, payload.peers).await?;
                    match (post_login_object.rtdb, post_login_object.google_auth_jwt) {
                        (Some(rtdb_cfg), Some(jwt)) => {
                            log::info!("Client detected RTDB config + Google Auth web token. Will login + store config to CNAC ...");
                            let rtdb = FirebaseRTDB::new_from_jwt(&rtdb_cfg.url, jwt.clone(), rtdb_cfg.api_key.clone()).await.map_err(|_| PrimaryProcessorResult::Void)?;// login

                            let FirebaseRTDB {
                                base_url, auth, expire_time, api_key, jwt, ..
                            } = rtdb;

                            let client_rtdb_config = RtdbClientConfig { url: base_url, api_key, auth_payload: auth, expire_time, jwt };
                            cnac.visit_mut(|mut inner| {
                               inner.client_rtdb_config = Some(client_rtdb_config);
                            });

                            log::info!("Successfully logged-in to RTDB + stored config inside CNAC ...");
                        }

                        _ => {}
                    };

                    cnac.save().await?;

                    match connect_mode {
                        ConnectMode::Fetch { .. } => {
                            log::info!("[FETCH] complete ...");
                            // we can end the session now. The fcm packets have already been sent alongside the connect signal above
                            return PrimaryProcessorResult::EndSession("Fetch succeeded")
                        }

                        _ => {}
                    }

                    if use_ka {
                        let ka = hdp_packet_crafter::keep_alive::craft_keep_alive_packet(&hyper_ratchet, timestamp, security_level);
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

/// returns true if saving occured
pub(super) async fn handle_client_fcm_keys(fcm_keys: Option<FcmKeys>, cnac: &ClientNetworkAccount, persistence_handler: &PersistenceHandler) -> Result<bool, NetworkError> {
    if let Some(fcm_keys) = fcm_keys {
        log::info!("[FCM KEYS]: {:?}", &fcm_keys);
        persistence_handler.update_fcm_keys(cnac, fcm_keys).await.map(|_| true).map_err(|err| NetworkError::Generic(err.into_string()))
    } else {
        Ok(false)
    }
}