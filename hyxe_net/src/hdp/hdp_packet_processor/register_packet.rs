use super::includes::*;
use std::sync::atomic::Ordering;
use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransfer};

/// This will handle an HDP registration packet
#[inline]
pub fn process(session: &HdpSession, packet: HdpPacket, remote_addr: SocketAddr) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session);
    if session.state != SessionState::NeedsRegister {
        if session.state != SessionState::SocketJustOpened {
            log::error!("Register packet received, but the system's state is not NeedsRegister. Dropping packet");
            return PrimaryProcessorResult::Void;
        }
    }

    let (header, payload, _, _) = packet.decompose();
    let ref header = LayoutVerified::new(&header[..])? as LayoutVerified<&[u8], HdpHeader>;
    debug_assert_eq!(packet_flags::cmd::primary::DO_REGISTER, header.cmd_primary);
    let security_level = header.security_level.into();

    match header.cmd_aux {
        packet_flags::cmd::aux::do_register::STAGE0 => {
            log::info!("STAGE 0 REGISTER PACKET");
            let mut state_container = inner_mut!(session.state_container);
            // This node is Bob (receives a stage 0 packet from Alice). The payload should have Alice's public key
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE0 {
                let algorithm = header.algorithm;
                match validation::do_register::validate_stage0(header, &*payload) {
                    Some((transfer, possible_cids)) => {
                        // Now, create a stage 1 packet
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let local_nid = session.account_manager.get_local_nid();

                        let reserved_true_cid = session.account_manager.get_local_nac().find_first_valid_cid(&possible_cids)?;
                        let bob_constructor = HyperRatchetConstructor::new_bob(header.algorithm, reserved_true_cid, 0, transfer)?;
                        let transfer = bob_constructor.stage0_bob()?;


                        let stage1_packet = hdp_packet_crafter::do_register::craft_stage1(algorithm, timestamp, local_nid, transfer, reserved_true_cid);
                        //let mut state_container = inner_mut!(session.state_container);
                        state_container.register_state.proposed_cid = Some(reserved_true_cid);
                        state_container.register_state.created_hyper_ratchet = Some(bob_constructor.finish()?);
                        state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE1;
                        state_container.register_state.on_register_packet_received();

                        PrimaryProcessorResult::ReplyToSender(stage1_packet)
                    }

                    _ => {
                        log::error!("Unable to validate STAGE0_REGISTER packet");
                        let timestamp = session.time_tracker.get_global_time_ns();
                        state_container.register_state.on_fail(timestamp);
                        state_container.register_state.on_register_packet_received();
                        std::mem::drop(state_container);

                        session.state = SessionState::NeedsRegister;

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
                if let Some(mut alice_constructor) = state_container.register_state.constructor.take() {
                    let transfer = BobToAliceTransfer::deserialize_from(payload)?;
                    let security_level = transfer.security_level;
                    alice_constructor.stage1_alice(transfer)?;
                    let new_hyper_ratchet = alice_constructor.finish()?;

                    let reserved_true_cid = header.group.get();
                    let timestamp = session.time_tracker.get_global_time_ns();
                    let local_nid = session.account_manager.get_local_nid();

                    let proposed_credentials = state_container.register_state.proposed_credentials.as_ref()?;

                    let stage2_packet = hdp_packet_crafter::do_register::craft_stage2(&new_hyper_ratchet, algorithm, local_nid, timestamp, proposed_credentials, security_level);
                    //let mut state_container = inner_mut!(session.state_container);

                    state_container.register_state.proposed_cid = Some(reserved_true_cid);
                    state_container.register_state.created_hyper_ratchet = Some(new_hyper_ratchet);
                    state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE2;
                    state_container.register_state.on_register_packet_received();

                    PrimaryProcessorResult::ReplyToSender(stage2_packet)
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
            // Bob receives this packet. It contains the proposed credentials. We need to register and we're good to go
            let mut state_container = inner_mut!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE1 {
                let algorithm = header.algorithm;
                let hyper_ratchet = state_container.register_state.created_hyper_ratchet.as_ref()?;
                    if let Some((proposed_credentials, adjacent_nac)) = validation::do_register::validate_stage2(hyper_ratchet, header, payload, remote_addr) {
                        let (username, password, full_name, password_nonce) = proposed_credentials.decompose();
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let local_nid = session.account_manager.get_local_nid();
                        let reserved_true_cid = state_container.register_state.proposed_cid.clone()?;
                        // we must now create the CNAC
                        match session.account_manager.register_impersonal_hyperlan_client_network_account(reserved_true_cid, adjacent_nac, &username, password, full_name, Vec::from(&password_nonce as &[u8]), hyper_ratchet) {
                            Ok(peer_cnac) => {
                                log::info!("Server successfully created a CNAC during the DO_REGISTER process! CID: {}", peer_cnac.get_id());
                                let success_message = session.create_register_success_message();
                                let packet = hdp_packet_crafter::do_register::craft_success(hyper_ratchet, algorithm, local_nid, timestamp, success_message, security_level);

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
                                // this shouldnt happen anymore
                                //session.session_manager.clear_provisional_session(&remote_addr);
                                inner_mut!(session.state_container).register_state.on_register_packet_received();
                                PrimaryProcessorResult::EndSession("CID taken")
                            }

                            Err(err) => {
                                let err = err.to_string();
                                log::error!("Server unsuccessfully created a CNAC during the DO_REGISTER process. Reason: {}", &err);
                                let packet = hdp_packet_crafter::do_register::craft_failure(algorithm, local_nid, timestamp, err);

                                state_container.register_state.on_fail(timestamp);
                                state_container.register_state.on_register_packet_received();
                                std::mem::drop(state_container);

                                //session.session_manager.clear_provisional_session(&remote_addr);
                                PrimaryProcessorResult::ReplyToSender(packet)
                            }
                        }
                    } else {
                        log::error!("Unable to validate stage2 packet. Aborting");
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
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE2 {
                let hyper_ratchet = state_container.register_state.created_hyper_ratchet.clone()?;

                    if let Some((success_message, adjacent_nac)) = validation::do_register::validate_success(&hyper_ratchet, header, payload, remote_addr) {
                        // Now, register the CNAC locally

                        let credentials = state_container.register_state.proposed_credentials.take()?;
                        let (username, password, full_name, nonce) = credentials.decompose();
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let reserved_true_cid = state_container.register_state.proposed_cid.clone()?;

                        // &self, cnac_inner_bytes: T, username: R, full_name: V, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>
                        match session.account_manager.register_personal_hyperlan_server(reserved_true_cid, hyper_ratchet.clone(), username, full_name, adjacent_nac, password, Vec::from(&nonce as &[u8])) {
                            Ok(new_cnac) => {
                                // Finally, alert the higher-level kernel about the success
                                state_container.register_state.on_success(timestamp);
                                std::mem::drop(state_container);
                                //session.session_manager.clear_provisional_session(&remote_addr);
                                session.send_to_kernel(HdpServerResult::RegisterOkay(session.kernel_ticket, new_cnac, success_message))?;
                            }

                            Err(err) => {
                                state_container.register_state.on_fail(timestamp);
                                std::mem::drop(state_container);
                                //session.session_manager.clear_provisional_session(&remote_addr);
                                session.send_to_kernel(HdpServerResult::RegisterFailure(session.kernel_ticket, err.to_string()))?;
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
                warn!("Inconsistency between the session's stage and the packet's state. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_register::FAILURE => {
            log::info!("STAGE FAILURE REGISTER PACKET");
            // This node is again Bob. Alice received Bob's stage1 packet, but was unable to connect
            // A failure can be sent at any stage greater than the zeroth
            if inner!(session.state_container).register_state.last_stage > packet_flags::cmd::aux::do_register::STAGE0 {
                if let Some(error_message) = validation::do_register::validate_failure(header, &payload[..]) {
                    session.send_to_kernel(HdpServerResult::RegisterFailure(session.kernel_ticket, String::from_utf8(error_message).unwrap_or("Non-UTF8 error message".to_string())))?;
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
