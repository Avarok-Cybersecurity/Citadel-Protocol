//! Registration Packet Processor for Citadel Protocol
//!
//! This module handles the registration process for new clients in the Citadel Protocol
//! network. It implements a secure multi-stage handshake that establishes client
//! identity and sets up initial cryptographic parameters.
//!
//! # Features
//!
//! - Multi-stage registration handshake
//! - Secure key exchange
//! - Passwordless registration support
//! - Session state management
//! - Cryptographic parameter negotiation
//! - Registration failure handling
//!
//! # Important Notes
//!
//! - Requires specific session states (NeedsRegister, SocketJustOpened, NeedsConnect)
//! - Supports both password-based and passwordless registration
//! - Implements post-quantum cryptography
//! - Manages registration state transitions
//! - Validates registration parameters
//!
//! # Related Components
//!
//! - `StateContainer`: Manages registration state
//! - `AccountManager`: Handles account creation
//! - `StackedRatchet`: Provides cryptographic primitives
//! - `SessionManager`: Tracks registration process

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::node_result::{RegisterFailure, RegisterOkay};
use citadel_crypt::endpoint_crypto_container::{
    AssociatedCryptoParams, AssociatedSecurityLevel, EndpointRatchetConstructor, PeerSessionCrypto,
};
use citadel_crypt::prelude::{ConstructorOpts, Toolset};
use citadel_crypt::ratchets::Ratchet;
use citadel_user::serialization::SyncIO;

/// This will handle a registration packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_register<R: Ratchet>(
    session_ref: &CitadelSession<R>,
    packet: HdpPacket,
    remote_addr: SocketAddr,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref.clone();
    let state = session.state.get();

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
                let task = { // Scoping for state_container lock
                    let mut state_container = inner_mut_state!(session.state_container);
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE0
                    {
                        let algorithm = header.algorithm;

                        match validation::do_register::validate_stage0::<R>(&payload) {
                            Some((transfer, passwordless)) => {
                                let timestamp = session.time_tracker.get_global_time_ns();
                                state_container.register_state.passwordless = Some(passwordless);

                                if passwordless
                                    && !session
                                        .account_manager
                                        .get_misc_settings()
                                        .allow_passwordless
                                {
                                    let err = packet_crafter::do_register::craft_failure(algorithm, timestamp, "Passwordless connections are not enabled on the target node", header.session_cid.get());
                                    return Ok(PrimaryProcessorResult::ReplyToSender(err));
                                }
                                // Drop lock before inner async block
                                std::mem::drop(state_container);
                                let session_password = session.session_password.clone();
                                let session_clone_stage0 = session.clone(); // Clone for inner async block

                                async move { // Inner async block
                                    let cid = header.session_cid.get();
                                    let mut bob_constructor =
                                        <R::Constructor as EndpointRatchetConstructor<R>>::new_bob(
                                            cid,
                                            ConstructorOpts::new_vec_init(
                                                Some(transfer.crypto_params()),
                                                transfer.security_level(),
                                            ),
                                            transfer,
                                            session_password.as_ref(),
                                        )
                                        .ok_or(NetworkError::InvalidRequest("Bad bob transfer"))?;
                                    let transfer_bob = return_if_none!( // Renamed to avoid conflict
                                        bob_constructor.stage0_bob(),
                                        "Unable to advance past stage0-bob"
                                    );

                                    let stage1_packet =
                                        packet_crafter::do_register::craft_stage1::<R>(
                                            algorithm,
                                            timestamp,
                                            transfer_bob, // Use renamed variable
                                            header.session_cid.get(),
                                        );

                                    // Re-acquire lock for modification
                                    let mut state_container_inner = inner_mut_state!(session_clone_stage0.state_container);
                                    state_container_inner.register_state.created_ratchet =
                                        Some(return_if_none!(
                                            bob_constructor.finish(),
                                            "Unable to finish bob constructor"
                                        ));
                                    state_container_inner.register_state.last_stage =
                                        packet_flags::cmd::aux::do_register::STAGE1;
                                    state_container_inner.register_state.on_register_packet_received();

                                    Ok(PrimaryProcessorResult::ReplyToSender(stage1_packet))
                                }
                            }

                            _ => { // Error in validate_stage0
                                log::error!(target: "citadel", "Unable to validate STAGE0_REGISTER packet");
                                state_container.register_state.on_fail();
                                state_container.register_state.on_register_packet_received();
                                // Lock `state_container` is dropped when this scope ends
                                std::mem::drop(state_container);
                                session.state.set(SessionState::NeedsRegister); // DualCell, atomic, fine
                                return Ok(PrimaryProcessorResult::EndSession(
                                    "Unable to validate STAGE0_REGISTER packet",
                                ));
                            }
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void); // state_container lock drops
                    }
                };

                task.await // Await the inner async block for STAGE0
            }

            packet_flags::cmd::aux::do_register::STAGE1 => {
                log::trace!(target: "citadel", "STAGE 1 REGISTER PACKET");
                // Node is Alice. This packet will contain Bob's ciphertext; Alice will now be able to create the shared private key

                // Clone necessary variables for spawn_blocking
                let session_clone_stage1 = session.clone();
                let payload_clone_stage1 = payload.clone(); // BytesMut is cheap to clone (Arc inner)
                let algorithm_stage1 = header.algorithm;
                let security_level_stage1 = security_level; // Already a value
                let timestamp_stage1 = session.time_tracker.get_global_time_ns();


                tokio::task::spawn_blocking(move || {
                    let mut state_container = inner_mut_state!(session_clone_stage1.state_container);
                    if state_container.register_state.last_stage
                        != packet_flags::cmd::aux::do_register::STAGE0
                    {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state for STAGE1. Dropping");
                        return Ok(PrimaryProcessorResult::Void);
                    }

                    if let Some(mut alice_constructor) =
                        state_container.register_state.constructor.take()
                    {
                        let transfer: <R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer =
                            SyncIO::deserialize_from_vector(&payload_clone_stage1[..]).map_err(|_| NetworkError::DeSerializationError("Unable to deserialize BobToAliceTransfer"))?;

                        alice_constructor
                            .stage1_alice(transfer, session_clone_stage1.session_password.as_ref())
                            .map_err(|err| NetworkError::Generic(err.to_string()))?;

                        let new_ratchet = alice_constructor.finish().ok_or(NetworkError::InternalError("Unable to finish alice constructor"))?;

                        let proposed_credentials = state_container.connect_state.proposed_credentials.as_ref()
                            .ok_or(NetworkError::InternalError("Unable to load proposed credentials (STAGE1)"))?;

                        let stage2_packet = packet_crafter::do_register::craft_stage2(
                            &new_ratchet,
                            algorithm_stage1,
                            timestamp_stage1,
                            proposed_credentials,
                            security_level_stage1, // Use the original security_level from header
                        );

                        state_container.register_state.created_ratchet = Some(new_ratchet);
                        state_container.register_state.last_stage =
                            packet_flags::cmd::aux::do_register::STAGE2;
                        state_container.register_state.on_register_packet_received();

                        Ok(PrimaryProcessorResult::ReplyToSender(stage2_packet))
                    } else {
                        log::error!(target: "citadel", "Register stage is one, yet, no PQC is present. Aborting.");
                        Ok(PrimaryProcessorResult::Void)
                    }
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for STAGE1 failed: {}", e)))?
            }

            packet_flags::cmd::aux::do_register::STAGE2 => {
                log::trace!(target: "citadel", "STAGE 2 REGISTER PACKET");
                let task = {
                    let state_container = inner_state!(session.state_container); // Read lock, dropped before await
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE1
                    {
                        let algorithm = header.algorithm;
                        let ratchet_clone = return_if_none!( // Clone for spawn_blocking
                            state_container.register_state.created_ratchet.clone(),
                            "Unable to load created hyper ratchet"
                        );
                        // Clone/own necessary data for spawn_blocking
                        let header_bytes_stage2 = header.bytes().to_vec(); // Owned bytes
                        let payload_clone_stage2 = payload.clone(); // BytesMut is cheap to clone

                        let validation_result_stage2 = tokio::task::spawn_blocking(move || {
                            // Reconstruct Ref if necessary from header_bytes_stage2, or adjust validate_stage2
                            // Assuming validate_stage2 can work with owned data or Ref can be reconstructed
                            let header_ref_stage2 = Ref::new(&header_bytes_stage2[..]).unwrap();
                            validation::do_register::validate_stage2(
                                &ratchet_clone,
                                &header_ref_stage2,
                                payload_clone_stage2,
                                remote_addr,
                            )
                        }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for validate_stage2 failed: {}", e)))?;

                        if let Some((stage2_packet, conn_info)) = validation_result_stage2 {
                            let creds = stage2_packet.credentials;
                            let timestamp = session.time_tracker.get_global_time_ns();
                            let account_manager = session.account_manager.clone();
                            std::mem::drop(state_container); // Drop read lock
                            let session_clone_stage2 = session.clone(); // Clone for inner async

                            let session_crypto_state = initialize_peer_session_crypto(
                                ratchet.get_cid(),
                                ratchet.clone(), // Ratchet is R: Ratchet, which should be Clone
                                true,
                            );
                            async move {
                                match account_manager
                                    .register_impersonal_hyperlan_client_network_account(
                                        conn_info,
                                        creds,
                                        session_crypto_state,
                                    )
                                    .await // IO-bound
                                {
                                    Ok(peer_cnac) => {
                                        log::trace!(target: "citadel", "Server successfully created a CNAC during the DO_REGISTER process! CID: {}", peer_cnac.get_cid());
                                        let success_message =
                                            session_clone_stage2.create_register_success_message();

                                        let packet = packet_crafter::do_register::craft_success(
                                            &ratchet, // Ratchet was cloned
                                            algorithm,
                                            timestamp,
                                            success_message,
                                            security_level,
                                        );
                                        Ok(PrimaryProcessorResult::ReplyToSender(packet))
                                    }
                                    Err(err) => {
                                        let err_str = err.into_string();
                                        log::error!(target: "citadel", "Server unsuccessfully created a CNAC during the DO_REGISTER process. Reason: {}", &err_str);
                                        let packet = packet_crafter::do_register::craft_failure(
                                            algorithm,
                                            timestamp,
                                            err_str,
                                            header.session_cid.get(),
                                        );
                                        session_clone_stage2.session_manager.clear_provisional_session(
                                            &remote_addr,
                                            session_clone_stage2.init_time,
                                        );
                                        Ok(PrimaryProcessorResult::ReplyToSender(packet))
                                    }
                                }
                            }
                        } else {
                            log::error!(target: "citadel", "Unable to validate stage2 packet. Aborting");
                            return Ok(PrimaryProcessorResult::Void); // state_container lock (read) drops
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void); // state_container lock (read) drops
                    }
                };
                task.await
            }

            packet_flags::cmd::aux::do_register::SUCCESS => {
                log::trace!(target: "citadel", "STAGE SUCCESS REGISTER PACKET");
                let task = {
                    let state_container = inner_state!(session.state_container); // Read lock, dropped before await
                    if state_container.register_state.last_stage
                        == packet_flags::cmd::aux::do_register::STAGE2
                    {
                        let ratchet_clone_success = return_if_none!( // Clone for spawn_blocking
                            state_container.register_state.created_ratchet.clone(),
                            "Unable to load created hyper ratchet"
                        );
                        // Clone/own necessary data for spawn_blocking
                        let header_bytes_success = header.bytes().to_vec(); // Owned bytes
                        let payload_clone_success = payload.clone(); // BytesMut is cheap to clone

                        let validation_result_success = tokio::task::spawn_blocking(move || {
                            let header_ref_success = Ref::new(&header_bytes_success[..]).unwrap();
                            validation::do_register::validate_success(
                                &ratchet_clone_success,
                                &header_ref_success,
                                payload_clone_success,
                                remote_addr,
                            )
                        }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for validate_success failed: {}", e)))?;

                        if let Some((success_message, conn_info)) = validation_result_success {
                            let credentials = return_if_none!(
                                state_container.connect_state.proposed_credentials.clone(),
                                "Unable to take proposed credentials"
                            );
                            let passwordless = return_if_none!(
                                state_container.register_state.passwordless,
                                "Passwordless unset (reg)"
                            );
                            drop(state_container); // Drop read lock

                            let reg_ticket = session.kernel_ticket.clone(); // DualCell, atomic, fine
                            let account_manager = session.account_manager.clone();
                            let kernel_tx = session.kernel_tx.clone();
                            let session_clone_success = session.clone(); // For async block

                            let session_crypto_state =
                                initialize_peer_session_crypto(ratchet.get_cid(), ratchet.clone(), false);

                            async move {
                                match account_manager
                                    .register_personal_hyperlan_server(
                                        session_crypto_state,
                                        credentials,
                                        conn_info,
                                    )
                                    .await // IO-bound
                                {
                                    Ok(new_cnac) => {
                                        if passwordless {
                                            // This section involves blocking calls to begin_connect and state_container writes
                                            let new_cnac_clone = new_cnac.clone();
                                            let session_for_blocking = session_clone_success.clone();
                                            tokio::task::spawn_blocking(move || {
                                                CitadelSession::begin_connect(&session_for_blocking, &new_cnac_clone)?;
                                                inner_mut_state!(session_for_blocking.state_container).cnac = Some(new_cnac_clone);
                                                Ok::<_, NetworkError>(())
                                            }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for passwordless connect failed: {}", e)))??;

                                            Ok(PrimaryProcessorResult::Void)
                                        } else {
                                            session_clone_success.session_manager.clear_provisional_session(
                                                &remote_addr,
                                                session_clone_success.init_time,
                                            );
                                            kernel_tx.unbounded_send(NodeResult::RegisterOkay(
                                                RegisterOkay {
                                                    ticket: reg_ticket.get(), // DualCell, atomic
                                                    cid: new_cnac.get_cid(),
                                                    welcome_message: success_message,
                                                },
                                            ))?;
                                            // session.shutdown() involves blocking lock
                                            let session_for_shutdown = session_clone_success.clone();
                                            tokio::task::spawn_blocking(move || {
                                                session_for_shutdown.shutdown();
                                            }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for shutdown failed: {}", e)))?;
                                            Ok(PrimaryProcessorResult::Void)
                                        }
                                    }
                                    Err(err) => {
                                        kernel_tx.unbounded_send(NodeResult::RegisterFailure(
                                            RegisterFailure {
                                                ticket: reg_ticket.get(), // DualCell, atomic
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
                            return Ok(PrimaryProcessorResult::Void); // state_container read lock drops
                        }
                    } else {
                        warn!(target: "citadel", "Inconsistency between the session's stage and the packet's state. Dropping");
                        return Ok(PrimaryProcessorResult::Void); // state_container read lock drops
                    }
                };
                task.await
            }

            packet_flags::cmd::aux::do_register::FAILURE => {
                log::trace!(target: "citadel", "STAGE FAILURE REGISTER PACKET");
                let session_clone_failure = session.clone(); // Clone for spawn_blocking

                tokio::task::spawn_blocking(move || {
                    if inner_state!(session_clone_failure.state_container) // Blocking read
                        .register_state
                        .last_stage
                        > packet_flags::cmd::aux::do_register::STAGE0
                    {
                        if let Some(error_message) =
                            validation::do_register::validate_failure(&header, &payload[..])
                        {
                            session_clone_failure.send_to_kernel(NodeResult::RegisterFailure(RegisterFailure { // Non-blocking channel send
                                ticket: session_clone_failure.kernel_ticket.get(), // DualCell, atomic
                                error_message: String::from_utf8(error_message)
                                    .unwrap_or_else(|_| "Non-UTF8 error message".to_string()),
                            }))?;
                            session_clone_failure.shutdown(); // Involves blocking lock
                        } else {
                            log::error!(target: "citadel", "Error validating FAILURE packet");
                            // Return Ok(Void) from the blocking task to match original flow, error will be handled by outer result
                            return Ok(PrimaryProcessorResult::Void);
                        }
                        Ok(PrimaryProcessorResult::EndSession(
                            "Registration subroutine ended (Status: FAIL)",
                        ))
                    } else {
                        log::warn!(target: "citadel", "A failure packet was received, but the program's registration did not advance past stage 0. Dropping");
                        Ok(PrimaryProcessorResult::Void)
                    }
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for FAILURE failed: {}", e)))?
            }

            _ => {
                warn!(target: "citadel", "Invalid auxiliary command. Dropping packet");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}

// Only for registration; does not start the messenger/ratchet manager
fn initialize_peer_session_crypto<R: Ratchet>(
    cid: u64,
    initial_ratchet: R,
    is_server: bool,
) -> PeerSessionCrypto<R> {
    PeerSessionCrypto::new(Toolset::new(cid, initial_ratchet), !is_server)
}
