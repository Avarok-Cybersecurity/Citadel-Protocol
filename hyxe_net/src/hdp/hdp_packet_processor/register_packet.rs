use super::includes::*;
use std::sync::atomic::Ordering;
use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransfer, BobToAliceTransferType};
use crate::error::NetworkError;
use hyxe_crypt::argon_container::{ClientArgonContainer, ArgonContainerType};

/// This will handle an HDP registration packet
#[inline]
pub async fn process(session_ref: &HdpSession, packet: HdpPacket, remote_addr: SocketAddr) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session_ref);
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

                        let account_manager = session.account_manager.clone();

                        std::mem::drop(state_container);
                        std::mem::drop(session);

                        let reserved_true_cid = account_manager.get_persistence_handler().find_first_valid_cid(&possible_cids).await?.ok_or(NetworkError::InvalidExternalRequest("Infinitesimally small probability this happens"))?;
                        let bob_constructor = HyperRatchetConstructor::new_bob(reserved_true_cid, 0, transfer).ok_or(NetworkError::InvalidExternalRequest("Bad bob transfer"))?;
                        let transfer = bob_constructor.stage0_bob()?;


                        let stage1_packet = hdp_packet_crafter::do_register::craft_stage1(algorithm, timestamp, local_nid, transfer, reserved_true_cid);
                        let session = inner!(session_ref);
                        let mut state_container = inner_mut!(session.state_container);
                        state_container.register_state.proposed_cid = Some(reserved_true_cid);
                        state_container.register_state.created_hyper_ratchet = Some(bob_constructor.finish()?);
                        state_container.register_state.last_stage = packet_flags::cmd::aux::do_register::STAGE1;
                        state_container.register_state.on_register_packet_received();

                        PrimaryProcessorResult::ReplyToSender(stage1_packet)
                    }

                    _ => {
                        log::error!("Unable to validate STAGE0_REGISTER packet");
                        state_container.register_state.on_fail();
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
                    let transfer = BobToAliceTransfer::deserialize_from(&payload[..])?;
                    let security_level = transfer.security_level;
                    alice_constructor.stage1_alice(&BobToAliceTransferType::Default(transfer))?;
                    let new_hyper_ratchet = alice_constructor.finish()?;

                    let reserved_true_cid = header.group.get();
                    let timestamp = session.time_tracker.get_global_time_ns();
                    let local_nid = session.account_manager.get_local_nid();

                    let proposed_credentials = state_container.register_state.proposed_credentials.as_ref()?;
                    let fcm_keys = session.fcm_keys.clone();

                    let stage2_packet = hdp_packet_crafter::do_register::craft_stage2(&new_hyper_ratchet, algorithm, local_nid, timestamp, proposed_credentials, fcm_keys, security_level);
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

            let state_container = inner!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE1 {
                let algorithm = header.algorithm;
                let hyper_ratchet = state_container.register_state.created_hyper_ratchet.clone()?;
                    if let Some((stage2_packet, adjacent_nac)) = validation::do_register::validate_stage2(&hyper_ratchet, header, payload, remote_addr, session.account_manager.get_persistence_handler()) {
                        let (username, password, full_name, _) = stage2_packet.credentials.decompose();
                        let timestamp = session.time_tracker.get_global_time_ns();
                        let local_nid = session.account_manager.get_local_nid();
                        let reserved_true_cid = state_container.register_state.proposed_cid.clone()?;
                        let account_manager = session.account_manager.clone();
                        std::mem::drop(state_container);
                        std::mem::drop(session);

                        // we must now create the CNAC
                        match account_manager.register_impersonal_hyperlan_client_network_account(reserved_true_cid, adjacent_nac, &username, password, full_name,  hyper_ratchet.clone(), stage2_packet.fcm_keys).await {
                            Ok(peer_cnac) => {
                                log::info!("Server successfully created a CNAC during the DO_REGISTER process! CID: {}", peer_cnac.get_id());
                                let session = inner_mut!(session_ref);

                                let success_message = session.create_register_success_message();
                                let packet = hdp_packet_crafter::do_register::craft_success(&hyper_ratchet, algorithm, local_nid, timestamp, success_message, security_level);

                                // We set this that way, once the adjacent node closes, this node won't get a propagated error message
                                session.needs_close_message.store(false, Ordering::SeqCst);
                                // below was moved above
                                //let _ = handle_client_fcm_keys(stage2_packet.fcm_keys, &peer_cnac);

                                PrimaryProcessorResult::ReplyToSender(packet)
                            }

                            Err(AccountError::ClientExists(taken_cid)) => {
                                log::error!("Attempted to register the new CNAC ({}) locally, but unfortunately the CID was taken", taken_cid);
                                PrimaryProcessorResult::EndSession("CID taken")
                            }

                            Err(err) => {
                                let err = err.into_string();
                                log::error!("Server unsuccessfully created a CNAC during the DO_REGISTER process. Reason: {}", &err);
                                let packet = hdp_packet_crafter::do_register::craft_failure(algorithm, local_nid, timestamp, err);

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
            let connect_proto = session.connect_proto.clone()?;
            // run: pub async fn register_personal_hyperlan_server<T: AsRef<[u8]>>(&self, cnac_inner_bytes: T, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>) -> Result<ClientNetworkAccount, AccountError<String>>
            let mut state_container = inner_mut!(session.state_container);
            if state_container.register_state.last_stage == packet_flags::cmd::aux::do_register::STAGE2 {
                let hyper_ratchet = state_container.register_state.created_hyper_ratchet.clone()?;

                    if let Some((success_message, adjacent_nac)) = validation::do_register::validate_success(&hyper_ratchet, header, payload, remote_addr, connect_proto,session.account_manager.get_persistence_handler()) {
                        // Now, register the CNAC locally

                        let credentials = state_container.register_state.proposed_credentials.take()?;
                        let (username, _password, full_name, argon_settings) = credentials.decompose();
                        let reserved_true_cid = state_container.register_state.proposed_cid.clone()?;
                        std::mem::drop(state_container);

                        let reg_ticket = session.kernel_ticket.clone();
                        let account_manager = session.account_manager.clone();
                        let kernel_tx = session.kernel_tx.clone();
                        let fcm_keys = session.fcm_keys.take();
                        let needs_close_message = session.needs_close_message.clone();
                        let argon_container = ArgonContainerType::Client(ClientArgonContainer::from(argon_settings?));


                        std::mem::drop(session);

                        // &self, cnac_inner_bytes: T, username: R, full_name: V, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>
                        match account_manager.register_personal_hyperlan_server(reserved_true_cid, hyper_ratchet, username, full_name, adjacent_nac, argon_container, fcm_keys).await {
                            Ok(new_cnac) => {
                                // Finally, alert the higher-level kernel about the success
                                kernel_tx.unbounded_send(HdpServerResult::RegisterOkay(reg_ticket, new_cnac, success_message))?;
                            }

                            Err(err) => {
                                kernel_tx.unbounded_send(HdpServerResult::RegisterFailure(reg_ticket, err.into_string()))?;
                            }
                        }

                        needs_close_message.store(false, Ordering::Relaxed);

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
