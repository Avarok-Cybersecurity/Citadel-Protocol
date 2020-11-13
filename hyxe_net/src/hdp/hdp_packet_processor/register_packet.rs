use super::includes::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// This will handle an HDP registration packet
#[inline]
pub fn process(session: &HdpSession, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8], remote_addr: SocketAddr) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session);
    if session.state != SessionState::NeedsRegister {
        if session.state != SessionState::SocketJustOpened {
            log::error!("Register packet received, but the system's state is not NeedsRegister. Dropping packet");
            return PrimaryProcessorResult::Void;
        } else {
            log::info!("Socket just opened, but will attempt registration reguardless ...");
        }
    }

    debug_assert_eq!(packet_flags::cmd::primary::DO_REGISTER, header.cmd_primary);

    match header.cmd_aux {
        packet_flags::cmd::aux::do_register::STAGE0 => {
            log::info!("STAGE 0 REGISTER PACKET");
            // This node is Bob (receives a stage 0 packet from Alice). The payload should have Alice's public key
            if inner!(session.state_container).register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE0 {
                let algorithm = header.algorithm;
                match PostQuantumContainer::new_bob(algorithm, payload) {
                    Ok(container_bob) => {
                        let ciphertext = container_bob.get_ciphertext()?;
                        debug_assert!(inner!(session.state_container).register_state.proposed_credentials.is_none());

                        // Now, create a stage 1 packet
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let local_nid = session.account_manager.get_local_nid();
                        let potential_cid_alice = header.group.get();
                        let potential_cid_bob = session.account_manager.get_local_nac().reserve_cid();

                        let reserved_true_cid = if potential_cid_alice >= potential_cid_bob {
                            potential_cid_alice
                        } else {
                            potential_cid_bob
                        };


                        let stage1_packet = hdp_packet_crafter::do_register::craft_stage1(algorithm, timestamp, local_nid, ciphertext, reserved_true_cid);
                        let mut state_container = inner_mut!(session.state_container);
                        state_container.register_state.proposed_cid = Some(reserved_true_cid);
                        state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE1;
                        state_container.register_state.on_register_packet_received();
                        std::mem::drop(state_container);

                        // we can store directly in here
                        session.post_quantum = Some(Arc::new(container_bob));

                        PrimaryProcessorResult::ReplyToSender(stage1_packet)
                    }

                    Err(err) => {
                        log::error!("Unable to create bob container (ERR: {}). Resetting register state ...", err.to_string());
                        session.state = SessionState::NeedsRegister;
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let mut state_container = inner_mut!(session.state_container);
                        state_container.register_state.on_fail(timestamp);
                        state_container.register_state.on_register_packet_received();

                        PrimaryProcessorResult::Void
                    }
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::STAGE1 => {
            log::info!("STAGE 1 REGISTER PACKET");
            // Node is Alice. This packet will contain Bob's ciphertext; Alice will now be able to create the shared private key
            let mut state_container = inner_mut!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE0 {
                let algorithm = header.algorithm;
                // pqc is stored in the register state container for now
                //debug_assert!(session.post_quantum.is_none());
                if let Some(post_quantum) = state_container.register_state.pqc.as_mut() {
                    let ciphertext = payload;
                    match post_quantum.alice_on_receive_ciphertext(ciphertext) {
                        Ok(_) => {
                            // At this point, the shared secrets are synchronized! Now, transmit the NONCE
                            let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
                            ThreadRng::default().fill_bytes(&mut nonce);
                            log::info!("Generated NONCE: {:?}", &nonce);
                            let timestamp = session.time_tracker.get_global_time_ns();
                            let local_nid = session.account_manager.get_local_nid();

                            let stage2_packet = hdp_packet_crafter::do_register::craft_stage2(&nonce, algorithm, local_nid, timestamp);
                            //let mut state_container = inner_mut!(session.state_container);
                            let reserved_true_cid = header.group.get();

                            state_container.register_state.proposed_cid = Some(reserved_true_cid);
                            state_container.register_state.nonce = Some(nonce);
                            state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE2;
                            state_container.register_state.on_register_packet_received();

                            PrimaryProcessorResult::ReplyToSender(stage2_packet)
                        }

                        Err(err) => {
                            log::error!("Error processing ciphertext. Ending registration process. ERR: {}", err.to_string());
                            let timestamp = session.time_tracker.get_global_time_ns();
                            //let mut state_container = inner_mut!(session.state_container);
                            state_container.register_state.on_fail(timestamp);
                            state_container.register_state.on_register_packet_received();
                            std::mem::drop(state_container);

                            session.state = SessionState::NeedsRegister;

                            PrimaryProcessorResult::Void
                        }
                    }
                } else {
                    log::error!("Register stage is one, yet, no PQC is present. Aborting.");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::STAGE2 => {
            log::info!("STAGE 2 REGISTER PACKET");
            // Bob receives this packet. It contains a nonce in the payload
            if inner!(session.state_container).register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE1 {
                let algorithm = header.algorithm;

                if let Some(_post_quantum) = session.post_quantum.as_ref() {
                    if let Some(nonce) = validation::do_register::validate_stage2(header, payload) {
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let local_nid = session.account_manager.get_local_nid();
                        let mut state_container = inner_mut!(session.state_container);
                        state_container.register_state.nonce = Some(nonce);
                        state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE3;
                        state_container.register_state.on_register_packet_received();

                        let stage3_packet = hdp_packet_crafter::do_register::craft_stage3(algorithm, local_nid, timestamp);
                        PrimaryProcessorResult::ReplyToSender(stage3_packet)
                    } else {
                        log::error!("Unable to validate stage2 packet. Aborting");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Register stage is two, yet, no PQC is present. Aborting.");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::STAGE3 => {
            log::info!("STAGE 3 REGISTER PACKET");
            // Alice receives this packet. This packet implies Bob received the nonce and is ready to receive the proposed username, password, full_name
            let mut state_container = inner_mut!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE2 {
                if validation::do_register::validate_stage3(header, payload) {
                    let algorithm = header.algorithm;

                    let timestamp = session.time_tracker.get_global_time_ns();
                    let local_nid = session.account_manager.get_local_nid();
                    state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE4;
                    state_container.register_state.on_register_packet_received();

                    let post_quantum = state_container.register_state.pqc.as_ref()?;
                    let nonce = state_container.register_state.nonce.as_ref()?;
                    let proposed_credentials = state_container.register_state.proposed_credentials.as_ref()?;
                    log::info!("Sending stage 4 packet");
                    let stage4_packet = hdp_packet_crafter::do_register::craft_stage4(nonce, algorithm, local_nid, timestamp, post_quantum, proposed_credentials);


                    PrimaryProcessorResult::ReplyToSender(stage4_packet)
                } else {
                    log::error!("Unable to validate stage3 packet. Aborting");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::STAGE4 => {
            log::info!("STAGE 4 REGISTER PACKET");
            // Bob receives this packet. It contains the encrypted username, password, and full name
            let state_borrow = inner!(session.state_container);
            if state_borrow.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE3 {
                let algorithm = header.algorithm;

                if let Some(post_quantum) = session.post_quantum.as_ref() {
                    let reserved_true_cid = state_borrow.register_state.proposed_cid.clone();
                    if let Some(nonce) = state_borrow.register_state.nonce.as_ref() {
                        if let Some((obtained_credentials, adjacent_nac)) = validation::do_register::validate_stage4(header, payload, nonce, post_quantum, remote_addr) {
                            // At this point, we either send a SUCCESS or FAILURE packet
                            log::info!("Proposed credentials: {:?}", &obtained_credentials);
                            let (username, password, full_name) = obtained_credentials.decompose();
                            let timestamp = session.time_tracker.get_global_time_ns();
                            let local_nid = session.account_manager.get_local_nid();
                            // pub async fn register_impersonal_hyperlan_client_network_account<T: ToString, R: ToString, V: ToString>(&self, nac_other: NetworkAccount, is_hyperwan_server: bool, username: T, password: R, full_name: V, post_quantum_container: &PostQuantumContainer) -> Result<ClientNetworkAccount, AccountError<String>>

                            match session.account_manager.register_impersonal_hyperlan_client_network_account(reserved_true_cid.unwrap(), adjacent_nac, &username, password, full_name, post_quantum) {
                                Ok(peer_cnac) => {
                                    log::info!("Server successfully created a CNAC during the DO_REGISTER process! CID: {}", peer_cnac.get_id());
                                    let success_message = session.create_register_success_message();
                                    let packet = hdp_packet_crafter::do_register::craft_success(&peer_cnac, algorithm, local_nid, timestamp, post_quantum, nonce, success_message);
                                    std::mem::drop(state_borrow);
                                    let mut state_container = inner_mut!(session.state_container);
                                    state_container.register_state.on_success(timestamp);
                                    state_container.register_state.on_register_packet_received();
                                    std::mem::drop(state_container);

                                    //session.session_manager.clear_provisional_session(&remote_addr);

                                    //PrimaryProcessorResult::FinalReply(packet)
                                    // We set this that way, once the adjacent node closes, this node won't get a propagated error message
                                    session.needs_close_message.store(false, Ordering::SeqCst);
                                    // we no longer use FinalReply, because that cuts the connection and end the future on the other end. Let the other end terminate it
                                    PrimaryProcessorResult::ReplyToSender(packet)
                                }

                                Err(AccountError::ClientExists(taken_cid)) => {
                                    log::error!("Attempted to register the new CNAC ({}) locally, but unfortunately the CID was taken", taken_cid);
                                    std::mem::drop(state_borrow);
                                    // this shouldnt happen anymore
                                    //session.session_manager.clear_provisional_session(&remote_addr);
                                    inner_mut!(session.state_container).register_state.on_register_packet_received();
                                    PrimaryProcessorResult::EndSession("CID taken")
                                }

                                Err(err) => {
                                    let err = err.to_string();
                                    log::error!("Server unsuccessfully created a CNAC during the DO_REGISTER process. Reason: {}", &err);
                                    let packet = hdp_packet_crafter::do_register::craft_failure(algorithm, local_nid, timestamp, err);
                                    std::mem::drop(state_borrow);
                                    let mut state_container = inner_mut!(session.state_container);
                                    state_container.register_state.on_fail(timestamp);
                                    state_container.register_state.on_register_packet_received();
                                    std::mem::drop(state_container);

                                    //session.session_manager.clear_provisional_session(&remote_addr);
                                    PrimaryProcessorResult::ReplyToSender(packet)
                                }
                            }
                        } else {
                            PrimaryProcessorResult::Void
                        }
                    } else {
                        log::error!("Bob does not have his nonce set, which is required for stage 4. Aborting");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Register stage is four, yet, no PQC is present. Aborting.");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::SUCCESS => {
            log::info!("STAGE SUCCESS REGISTER PACKET");
            // This will follow stage 4 in the case of a successful registration. The packet's payload contains the CNAC bytes, encrypted using AES-GCM.
            // The CNAC does not have the credentials (Serde skips the serialization thereof)
            // run: pub async fn register_personal_hyperlan_server<T: AsRef<[u8]>>(&self, cnac_inner_bytes: T, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>) -> Result<ClientNetworkAccount, AccountError<String>>
            let mut state_container = inner_mut!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE4 {
                let post_quantum = state_container.register_state.pqc.take()?;

                if let Some(nonce) = state_container.register_state.nonce.as_ref() {
                    if let Some((toolset_bytes, success_message)) = validation::do_register::validate_success(header, payload, nonce, &post_quantum) {
                        // Now, register the CNAC locally
                        let adjacent_nac = NetworkAccount::new_from_recent_connection(header.session_cid.get(), remote_addr);

                        //let mut state_container = inner_mut!(session.state_container);
                        let credentials = state_container.register_state.proposed_credentials.take()?;
                        let (username, password, full_name) = credentials.decompose();
                        let timestamp = session.time_tracker.get_global_time_ns();

                        // &self, cnac_inner_bytes: T, username: R, full_name: V, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>
                        match session.account_manager.register_personal_hyperlan_server(toolset_bytes, username, full_name, adjacent_nac, &post_quantum, password) {
                            Ok(new_cnac) => {
                                // Finally, alert the higher-level kernel about the success
                                state_container.register_state.on_success(timestamp);
                                std::mem::drop(state_container);
                                //session.session_manager.clear_provisional_session(&remote_addr);
                                session.send_to_kernel(HdpServerResult::RegisterOkay(session.kernel_ticket, new_cnac, success_message));
                                // now, reposition the pqc
                                session.post_quantum = Some(Arc::new(post_quantum));
                            }

                            Err(err) => {
                                state_container.register_state.on_fail(timestamp);
                                std::mem::drop(state_container);
                                //session.session_manager.clear_provisional_session(&remote_addr);
                                session.send_to_kernel(HdpServerResult::RegisterFailure(session.kernel_ticket, err.to_string()));
                            }
                        }
                        inner_mut!(session.state_container).register_state.on_register_packet_received();
                        // Send this to prevent double-sending to the kernel
                        session.needs_close_message.store(false, Ordering::SeqCst);
                        session.shutdown();
                        PrimaryProcessorResult::EndSession("Registration subroutine ended (STATUS: Success)")
                    } else {
                        log::error!("Unable to validate SUCCESS packet");
                        PrimaryProcessorResult::Void
                    }
                } else {
                    log::error!("Alice does not have her nonce set, which is required for the success stage. Aborting");
                    PrimaryProcessorResult::Void
                }
            } else {
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::FAILURE => {
            log::info!("STAGE FAILURE REGISTER PACKET");
            // This node is again Bob. Alice received Bob's stage1 packet, but was unable to connect
            // A failure can be sent at any stage greater than the zeroth
            if inner!(session.state_container).register_state.last_stage > packet_flags::cmd::aux::do_register::STAGE0 {
                if let Some(error_message) = validation::do_register::validate_failure(header, payload) {
                    session.send_to_kernel(HdpServerResult::RegisterFailure(session.kernel_ticket, String::from_utf8(error_message).unwrap_or("Non-UTF8 error message".to_string())));
                    //session.session_manager.clear_provisional_session(&remote_addr);
                    inner_mut!(session.state_container).register_state.on_register_packet_received();
                    session.needs_close_message.store(false, Ordering::SeqCst);
                    session.shutdown();
                } else {
                    log::error!("Error validating FAILURE packet");
                    return PrimaryProcessorResult::Void;
                }

                PrimaryProcessorResult::EndSession("Registration subroutine ended (Status: FAIL)")
            } else {
                log::warn!("A failure packet was received, but the program's registration did not advance past stage 0. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        _ => {
            warn!("Invalid auxiliary command. Dropping packet");
            PrimaryProcessorResult::Void
        }
    }
}
