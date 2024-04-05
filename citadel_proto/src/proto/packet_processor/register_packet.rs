use super::includes::*;
use crate::error::NetworkError;
use crate::proto::node_result::{RegisterFailure, RegisterOkay};
use citadel_crypt::prelude::ConstructorOpts;
use citadel_crypt::stacked_ratchet::constructor::{
    BobToAliceTransfer, BobToAliceTransferType, StackedRatchetConstructor,
};
use std::sync::atomic::Ordering;

/// This will handle a registration packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err, fields(is_server = session_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub async fn process_register(
    session_ref: &HdpSession,
    packet: HdpPacket,
    remote_addr: SocketAddr,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref.clone();
    let state = session.state.load(Ordering::Relaxed);

    if state != SessionState::NeedsRegister
        && state != SessionState::SocketJustOpened
        && state != SessionState::NeedsConnect
    {
        log::error!(target: "citadel", "Register packet received, but the system's state is not NeedsRegister. Dropping packet");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let (header, payload, _, _) = packet.decompose();
        let header = return_if_none!(Ref::new(&header[..]), "Unable to parse header")
            as Ref<&[u8], HdpHeader>;
        debug_assert_eq!(packet_flags::cmd::primary::DO_REGISTER, header.cmd_primary);
        let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_register::STAGE0 => {
                log::trace!(target: "citadel", "STAGE 0 REGISTER PACKET");
                let task = {
                    let mut state_container = inner_mut_state!(session.state_container);
                    // This node is Bob (receives a stage 0 packet from Alice). The payload should have Alice's public key
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE0
                    {
                        let algorithm = header.algorithm;

                        match validation::do_register::validate_stage0(&payload) {
                            Some((transfer, passwordless)) => {
                                // Now, create a stage 1 packet
                                let timestamp = session.time_tracker.get_global_time_ns();
                                state_container.register_state.passwordless = Some(passwordless);

                                if passwordless
                                    && !session
                                        .account_manager
                                        .get_misc_settings()
                                        .allow_passwordless
                                {
                                    // passwordless is not allowed on this node
                                    let err = packet_crafter::do_register::craft_failure(algorithm, timestamp, "Passwordless connections are not enabled on the target node", header.session_cid.get());
                                    return Ok(PrimaryProcessorResult::ReplyToSender(err));
                                }

                                std::mem::drop(state_container);

                                async move {
                                    let cid = header.session_cid.get();
                                    let bob_constructor = StackedRatchetConstructor::new_bob(
                                        cid,
                                        0,
                                        ConstructorOpts::new_vec_init(
                                            Some(transfer.params),
                                            (transfer.security_level.value() + 1) as usize,
                                        ),
                                        transfer,
                                    )
                                    .ok_or(NetworkError::InvalidRequest("Bad bob transfer"))?;
                                    let transfer = return_if_none!(
                                        bob_constructor.stage0_bob(),
                                        "Unable to advance past stage0-bob"
                                    );

                                    let stage1_packet = packet_crafter::do_register::craft_stage1(
                                        algorithm,
                                        timestamp,
                                        transfer,
                                        header.session_cid.get(),
                                    );

                                    let mut state_container =
                                        inner_mut_state!(session.state_container);
                                    state_container.register_state.created_hyper_ratchet =
                                        Some(return_if_none!(
                                            bob_constructor.finish(),
                                            "Unable to finish bob constructor"
                                        ));
                                    state_container.register_state.last_stage =
                                        packet_flags::cmd::aux::do_register::STAGE1;
                                    state_container.register_state.on_register_packet_received();

                                    Ok(PrimaryProcessorResult::ReplyToSender(stage1_packet))
                                }
                            }

                            _ => {
                                log::error!(target: "citadel", "Unable to validate STAGE0_REGISTER packet");
                                state_container.register_state.on_fail();
                                state_container.register_state.on_register_packet_received();
                                std::mem::drop(state_container);

                                session
                                    .state
                                    .store(SessionState::NeedsRegister, Ordering::Relaxed);

                                return Ok(PrimaryProcessorResult::Void);
                            }
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                task.await
            }

            packet_flags::cmd::aux::do_register::STAGE1 => {
                log::trace!(target: "citadel", "STAGE 1 REGISTER PACKET");
                // Node is Alice. This packet will contain Bob's ciphertext; Alice will now be able to create the shared private key
                let mut state_container = inner_mut_state!(session.state_container);
                if state_container.register_state.last_stage
                    == packet_flags::cmd::aux::do_register::STAGE0
                {
                    let algorithm = header.algorithm;

                    // pqc is stored in the register state container for now
                    //debug_assert!(session.post_quantum.is_none());
                    if let Some(mut alice_constructor) =
                        state_container.register_state.constructor.take()
                    {
                        let transfer = return_if_none!(
                            BobToAliceTransfer::deserialize_from(&payload[..]),
                            "Unable to deserialize BobToAliceTransfer"
                        );
                        let security_level = transfer.security_level;
                        alice_constructor
                            .stage1_alice(BobToAliceTransferType::Default(transfer))
                            .map_err(|err| NetworkError::Generic(err.to_string()))?;
                        let new_hyper_ratchet = return_if_none!(
                            alice_constructor.finish(),
                            "Unable to finish alice constructor"
                        );
                        let timestamp = session.time_tracker.get_global_time_ns();

                        let proposed_credentials = return_if_none!(
                            state_container.connect_state.proposed_credentials.as_ref(),
                            "Unable to load proposed credentials"
                        );

                        let stage2_packet = packet_crafter::do_register::craft_stage2(
                            &new_hyper_ratchet,
                            algorithm,
                            timestamp,
                            proposed_credentials,
                            security_level,
                        );
                        //let mut state_container = inner_mut!(session.state_container);

                        state_container.register_state.created_hyper_ratchet =
                            Some(new_hyper_ratchet);
                        state_container.register_state.last_stage =
                            packet_flags::cmd::aux::do_register::STAGE2;
                        state_container.register_state.on_register_packet_received();

                        Ok(PrimaryProcessorResult::ReplyToSender(stage2_packet))
                    } else {
                        log::error!(target: "citadel", "Register stage is one, yet, no PQC is present. Aborting.");
                        Ok(PrimaryProcessorResult::Void)
                    }
                } else {
                    warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            packet_flags::cmd::aux::do_register::STAGE2 => {
                log::trace!(target: "citadel", "STAGE 2 REGISTER PACKET");
                // Bob receives this packet. It contains the proposed credentials. We need to register and we're good to go

                let task = {
                    let state_container = inner_state!(session.state_container);
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE1
                    {
                        let algorithm = header.algorithm;
                        let hyper_ratchet = return_if_none!(
                            state_container.register_state.created_hyper_ratchet.clone(),
                            "Unable to load created hyper ratchet"
                        );
                        if let Some((stage2_packet, conn_info)) =
                            validation::do_register::validate_stage2(
                                &hyper_ratchet,
                                &header,
                                payload,
                                remote_addr,
                            )
                        {
                            let creds = stage2_packet.credentials;
                            let timestamp = session.time_tracker.get_global_time_ns();
                            let account_manager = session.account_manager.clone();
                            std::mem::drop(state_container);

                            // we must now create the CNAC
                            async move {
                                match account_manager
                                    .register_impersonal_hyperlan_client_network_account(
                                        conn_info,
                                        creds,
                                        hyper_ratchet.clone(),
                                    )
                                    .await
                                {
                                    Ok(peer_cnac) => {
                                        log::trace!(target: "citadel", "Server successfully created a CNAC during the DO_REGISTER process! CID: {}", peer_cnac.get_cid());
                                        let success_message =
                                            session.create_register_success_message();

                                        let packet = packet_crafter::do_register::craft_success(
                                            &hyper_ratchet,
                                            algorithm,
                                            timestamp,
                                            success_message,
                                            security_level,
                                        );
                                        // Do not shutdown the session here. It is up to the client to decide
                                        // how to shutdown, or continue (in the case of passwordless mode), the session
                                        Ok(PrimaryProcessorResult::ReplyToSender(packet))
                                    }

                                    Err(err) => {
                                        let err = err.into_string();
                                        log::error!(target: "citadel", "Server unsuccessfully created a CNAC during the DO_REGISTER process. Reason: {}", &err);
                                        let packet = packet_crafter::do_register::craft_failure(
                                            algorithm,
                                            timestamp,
                                            err,
                                            header.session_cid.get(),
                                        );

                                        session.session_manager.clear_provisional_session(
                                            &remote_addr,
                                            session.init_time,
                                        );

                                        Ok(PrimaryProcessorResult::ReplyToSender(packet))
                                    }
                                }
                            }
                        } else {
                            log::error!(target: "citadel", "Unable to validate stage2 packet. Aborting");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                task.await
            }

            packet_flags::cmd::aux::do_register::SUCCESS => {
                log::trace!(target: "citadel", "STAGE SUCCESS REGISTER PACKET");
                // This will follow stage 4 in the case of a successful registration. The packet's payload contains the CNAC bytes, encrypted using AES-GCM.
                // The CNAC does not have the credentials (Serde skips the serialization thereof)

                let task = {
                    let state_container = inner_state!(session.state_container);
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE2
                    {
                        let hyper_ratchet = return_if_none!(
                            state_container.register_state.created_hyper_ratchet.clone(),
                            "Unable to load created hyper ratchet"
                        );

                        if let Some((success_message, conn_info)) =
                            validation::do_register::validate_success(
                                &hyper_ratchet,
                                &header,
                                payload,
                                remote_addr,
                            )
                        {
                            // Now, register the CNAC locally
                            let credentials = return_if_none!(
                                state_container.connect_state.proposed_credentials.clone(),
                                "Unable to take proposed credentials"
                            );

                            let passwordless = return_if_none!(
                                state_container.register_state.passwordless,
                                "Passwordless unset (reg)"
                            );

                            drop(state_container);

                            let reg_ticket = session.kernel_ticket.clone();
                            let account_manager = session.account_manager.clone();
                            let kernel_tx = session.kernel_tx.clone();

                            async move {
                                match account_manager
                                    .register_personal_hyperlan_server(
                                        hyper_ratchet,
                                        credentials,
                                        conn_info,
                                    )
                                    .await
                                {
                                    Ok(new_cnac) => {
                                        if passwordless {
                                            HdpSession::begin_connect(&session, &new_cnac)?;
                                            inner_mut_state!(session.state_container).cnac =
                                                Some(new_cnac);
                                            // begin_connect will handle the connection process from here on out
                                            Ok(PrimaryProcessorResult::Void)
                                        } else {
                                            // Finally, alert the higher-level kernel about the success
                                            session.session_manager.clear_provisional_session(
                                                &remote_addr,
                                                session.init_time,
                                            );
                                            kernel_tx.unbounded_send(NodeResult::RegisterOkay(
                                                RegisterOkay {
                                                    ticket: reg_ticket.get(),
                                                    cnac: new_cnac,
                                                    welcome_message: success_message,
                                                },
                                            ))?;
                                            session.shutdown();
                                            Ok(PrimaryProcessorResult::Void)
                                        }
                                    }

                                    Err(err) => {
                                        kernel_tx.unbounded_send(NodeResult::RegisterFailure(
                                            RegisterFailure {
                                                ticket: reg_ticket.get(),
                                                error_message: err.into_string(),
                                            },
                                        ))?;
                                        Ok(PrimaryProcessorResult::EndSession(
                                            "Registration subroutine ended (STATUS: ERR)",
                                        ))
                                    }
                                }
                            }
                        } else {
                            log::error!(target: "citadel", "Unable to validate SUCCESS packet");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                task.await
            }

            packet_flags::cmd::aux::do_register::FAILURE => {
                log::trace!(target: "citadel", "STAGE FAILURE REGISTER PACKET");
                // This node is again Bob. Alice received Bob's stage1 packet, but was unable to connect
                // A failure can be sent at any stage greater than the zeroth
                if inner_state!(session.state_container)
                    .register_state
                    .last_stage
                    > packet_flags::cmd::aux::do_register::STAGE0
                {
                    if let Some(error_message) =
                        validation::do_register::validate_failure(&header, &payload[..])
                    {
                        session.send_to_kernel(NodeResult::RegisterFailure(RegisterFailure {
                            ticket: session.kernel_ticket.get(),
                            error_message: String::from_utf8(error_message)
                                .unwrap_or_else(|_| "Non-UTF8 error message".to_string()),
                        }))?;
                        //session.needs_close_message.set(false);
                        session.shutdown();
                    } else {
                        log::error!(target: "citadel", "Error validating FAILURE packet");
                        return Ok(PrimaryProcessorResult::Void);
                    }

                    Ok(PrimaryProcessorResult::EndSession(
                        "Registration subroutine ended (Status: FAIL)",
                    ))
                } else {
                    log::warn!(target: "citadel", "A failure packet was received, but the program's registration did not advance past stage 0. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            _ => {
                warn!(target: "citadel", "Invalid auxiliary command. Dropping packet");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}
