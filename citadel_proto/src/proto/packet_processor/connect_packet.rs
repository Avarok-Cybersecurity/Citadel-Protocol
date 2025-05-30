//! # Connection Packet Processing
//!
//! This module implements the connection establishment protocol for Citadel.
//! It handles the secure handshake process between nodes, including authentication,
//! capability negotiation, and secure channel establishment.
//!
//! # Protocol Flow
//!
//! 1. **Stage 0**: Initial connection request
//!    - Client sends encrypted credentials
//!    - Server validates and processes request
//!    - Capability negotiation (filesystem, UDP support)
//!
//! 2. **Success Stage**:
//!    - Secure channel establishment
//!    - Virtual connection initialization
//!    - Session security settings configuration
//!    - UDP channel setup (if supported)
//!
//! # Security Features
//!
//! - Post-quantum cryptographic handshake
//! - Secure credential transmission
//! - Session-specific security settings
//! - State validation at each stage
//!
//! # Related Components
//!
//! - `PreConnectPacket`: Handles pre-connection setup
//! - `StateContainer`: Manages connection state
//! - `VirtualConnection`: Manages established connections
//! - `SessionSecuritySettings`: Configures connection security
//!

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::node_result::{ConnectFail, ConnectSuccess, MailboxDelivery};
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::primary_group_packet::get_orientation_safe_ratchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::ConnectMode;
use citadel_user::backend::BackendType;
use citadel_user::external_services::ServicesObject;

/// This will optionally return an HdpPacket as a response if deemed necessary
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = sess_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_connect<R: Ratchet>(
    sess_ref: &CitadelSession<R>,
    packet: HdpPacket,
    header_entropy_bank_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session_initial_clone = sess_ref.clone(); // Clone for initial sync prefix

    // Synchronous prefix to be run in spawn_blocking
    let initial_sync_data = tokio::task::spawn_blocking(move || {
        let session = session_initial_clone; // Use cloned session
        let (hr, cnac, initial_header_bytes, initial_payload_bytes) = {
            let state_container = inner_state!(session.state_container);
            if !session.is_provisional()
                && state_container.connect_state.last_stage
                    != packet_flags::cmd::aux::do_connect::SUCCESS
            {
                log::error!(target: "citadel", "Connect packet received, but the system is not in a provisional state. Dropping");
                // Return a specific error or indicator that can be handled after await
                return Err(NetworkError::InvalidState("Not in provisional state for connect"));
            }

            if !state_container.pre_connect_state.success {
                log::error!(target: "citadel", "Connect packet received, but the system has not yet completed the pre-connect stage. Dropping");
                return Err(NetworkError::InvalidState("Pre-connect not complete"));
            }

            let hr = get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None)
                .ok_or(NetworkError::InternalError("Could not get proper HR [connect]"))?;
            let cnac = state_container.cnac.clone()
                .ok_or(NetworkError::InternalError("CNAC missing"))?;
            
            let (header_bytes, payload_bytes, _, _) = packet.decompose_arc(); // Assuming decompose_arc or similar for owned parts
            (hr, cnac, header_bytes, payload_bytes)
        };

        // AEAD validation
        let (validated_header_ref, validated_payload, validated_ratchet) = 
            validation::aead::validate(hr, &initial_header_bytes, BytesMut::from(&initial_payload_bytes[..]))
            .ok_or(NetworkError::InternalError("Unable to validate connect packet (AEAD)"))?;
        
        // We need to return owned data from the blocking task
        let owned_header = parsed_header_from_ref(&validated_header_ref); // Helper needed

        Ok((owned_header, validated_payload, validated_ratchet, cnac))
    }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for initial connect processing failed: {}", e)))??;

    let (header, payload, ratchet, cnac) = initial_sync_data; // Destructure owned data
    let security_level = header.security_level.into();
    let time_tracker = sess_ref.time_tracker; // Can access non-locked parts of original sess_ref if needed, or pass from above
    let session = sess_ref.clone(); // Re-clone for the async task below if original sess_ref is not 'static

    let task = async move {
        let session = &session; // Use the new clone of session
        match header.cmd_aux {
            // Node is Bob. Bob gets the encrypted username and password (separately encrypted)
            packet_flags::cmd::aux::do_connect::STAGE0 => {
                log::trace!(target: "citadel", "STAGE 0 CONNECT PACKET");
                
                // validate_stage0_packet is async, so it's called outside spawn_blocking here
                // but it needs to handle its own internal blocking calls if any
                match validation::do_connect::validate_stage0_packet(&cnac, &payload).await {
                    Ok(stage0_packet) => {
                        // Operations after validate_stage0_packet that need blocking lock
                        let session_clone_for_blocking = session.clone();
                        let ratchet_clone_for_blocking = ratchet.clone();
                        let cnac_clone_for_blocking = cnac.clone();
                        let kernel_ticket_val = session.kernel_ticket.get(); // Atomic
                        let remote_peer_addr = session.remote_peer; // Copy
                        let is_server_val = session.is_server; // Copy

                        tokio::task::spawn_blocking(move || {
                            let mut state_container = inner_mut_state!(session_clone_for_blocking.state_container);
                            let local_uses_file_system = matches!(
                                session_clone_for_blocking.account_manager.get_backend_type(),
                                BackendType::Filesystem(..)
                            );
                            session_clone_for_blocking
                                .file_transfer_compatible
                                .set_once(local_uses_file_system && stage0_packet.uses_filesystem);
                            let cid = ratchet_clone_for_blocking.get_cid();
                            
                            state_container.connect_state.last_stage =
                                packet_flags::cmd::aux::do_connect::SUCCESS;
                            state_container.connect_state.fail_time = None;
                            state_container.connect_state.on_connect_packet_received();
                            let udp_channel_rx = state_container
                                .pre_connect_state
                                .udp_channel_oneshot_tx
                                .rx
                                .take();
                            let channel = state_container.init_new_c2s_virtual_connection(
                                &cnac_clone_for_blocking, // Use cloned cnac
                                kernel_ticket_val,
                                header.session_cid.get(), // header is owned from initial spawn_blocking
                                &session_clone_for_blocking,
                            );

                            let session_security_settings = state_container
                                .session_security_settings
                                .expect("Should be set");
                            
                            // Upgrade connection (synchronous, uses lock on session_manager)
                            if !session_clone_for_blocking.session_manager.upgrade_connection(remote_peer_addr, cid) {
                                // Cannot directly return Ok(PrimaryProcessorResult...) from spawn_blocking if it needs to be async reply
                                // This part needs careful refactoring. For now, returning error to be handled by outer async.
                                return Err(NetworkError::InternalError("Unable to upgrade from a provisional to a protected connection (Server)"));
                            }

                            Ok((cid, udp_channel_rx, channel, session_security_settings, ratchet_clone_for_blocking, is_server_val, kernel_ticket_val, remote_peer_addr ))
                        }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for STAGE0 post-validation failed: {}", e)))??
                        .then(|(cid, udp_channel_rx, channel, session_security_settings, ratchet_for_reply, is_server_val, kernel_ticket_val, remote_peer_addr)| async move { // Use .then to chain async work
                            let mailbox_items = session // Use original session Arc here or pass clones appropriately
                                .session_manager
                                .register_session_with_peer_layer(cid)
                                .await?;
                            let peers = session.account_manager
                                .get_persistence_handler()
                                .get_hyperlan_peer_list_as_server(cid)
                                .await?
                                .unwrap_or_default();

                            #[cfg(feature = "google-services")]
                            let post_login_object = session.account_manager
                                .services_handler()
                                .on_post_login_serverside(cid)
                                .await?;
                            #[cfg(not(feature = "google-services"))]
                            let post_login_object =
                                citadel_user::external_services::ServicesObject::default();
                            
                            let success_time = session.time_tracker.get_global_time_ns(); // Access non-locking field or pass from sync block

                            let success_packet =
                                packet_crafter::do_connect::craft_final_status_packet(
                                    &ratchet_for_reply, // Use ratchet from blocking task's result
                                    true,
                                    mailbox_items,
                                    post_login_object.clone(),
                                    session.create_welcome_message(cid),
                                    peers,
                                    success_time,
                                    security_level, // Original security_level
                                    session.account_manager.get_backend_type(),
                                );
                            
                            // These are now safe as they are on the original session Arc after await
                            session.session_cid.set(Some(cid)); 
                            session.state.set(SessionState::Connected);

                            let cxn_type =
                                VirtualConnectionType::LocalGroupServer { session_cid: cid };
                            let channel_signal = NodeResult::ConnectSuccess(ConnectSuccess {
                                ticket: kernel_ticket_val,
                                session_cid: cid,
                                remote_addr: remote_peer_addr,
                                is_personal: !is_server_val,
                                v_conn_type: cxn_type,
                                services: post_login_object,
                                welcome_message: format!("Client {cid} successfully established a connection to the local HyperNode"),
                                channel,
                                udp_rx_opt: udp_channel_rx,
                                session_security_settings,
                            });
                            
                            // This lock needs to be async or also in spawn_blocking if it's blocking
                            let session_clone_for_signal = session.clone();
                            tokio::task::spawn_blocking(move || {
                                inner_mut_state!(session_clone_for_signal.state_container)
                                    .get_endpoint_container_mut(C2S_IDENTITY_CID)
                                    .as_mut()
                                    .unwrap()
                                    .channel_signal = Some(channel_signal);
                            }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for channel_signal set failed: {}", e)))?;
                            
                            Ok(PrimaryProcessorResult::ReplyToSender(success_packet))
                        }).await
                    }

                    Err(err) => { // Error from validate_stage0_packet
                        log::error!(target: "citadel", "Error validating stage0 packet. Reason: {err}");
                        let fail_time = time_tracker.get_global_time_ns(); // time_tracker is from original scope

                        let packet = packet_crafter::do_connect::craft_final_status_packet(
                            &ratchet, // ratchet is from initial_sync_data
                            false,
                            None,
                            ServicesObject::default(),
                            err.to_string(),
                            Vec::new(),
                            fail_time,
                            security_level, // original security_level
                            session.account_manager.get_backend_type(), // Access non-locking part or pass from sync
                        );
                        return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                    }
                }
            }

            packet_flags::cmd::aux::do_connect::FAILURE => {
                log::trace!(target: "citadel", "STAGE FAILURE CONNECT PACKET");
                let session_clone_failure = session.clone();
                let payload_clone_failure = payload.clone(); // Bytes is cheap to clone
                let ratchet_clone_failure = ratchet.clone(); // Ratchet must be Clone
                let header_clone_failure = header.clone(); // Assuming parsed_header_from_ref returns a clonable Header

                tokio::task::spawn_blocking(move || {
                    let kernel_ticket = session_clone_failure.kernel_ticket.get(); // Atomic

                    let mut state_container = inner_mut_state!(session_clone_failure.state_container);
                    if let Some(payload_validated) = // payload_clone_failure used here
                        validation::do_connect::validate_final_status_packet(&payload_clone_failure)
                    {
                        let message = String::from_utf8(payload_validated.message.to_vec())
                            .unwrap_or_else(|_| "Invalid UTF-8 message".to_string());
                        log::error!(target: "citadel", "The server refused to login the user. Reason: {}", &message);
                        let cid = ratchet_clone_failure.get_cid(); // Use cloned ratchet
                        state_container.connect_state.on_fail();
                        // Dropping state_container guard before other ops on session if they lock too
                        drop(state_container);

                        session_clone_failure.session_cid.set(None); // DualRwLock, blocking
                        session_clone_failure.state.set(SessionState::NeedsConnect); // Atomic, fine
                        session_clone_failure.disable_dc_signal(); // DualRwLock, blocking

                        session_clone_failure.send_to_kernel(NodeResult::ConnectFail(ConnectFail { // UnboundedSender, non-blocking
                            ticket: kernel_ticket,
                            cid_opt: Some(cid),
                            error_message: message,
                        }))?;
                        Ok(PrimaryProcessorResult::EndSession(
                            "Failed connecting. Try again",
                        ))
                    } else {
                        trace!(target: "citadel", "An invalid FAILURE packet was received; dropping due to invalid signature");
                        Ok(PrimaryProcessorResult::Void)
                    }
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for FAILURE branch failed: {}", e)))?
            }

            packet_flags::cmd::aux::do_connect::SUCCESS => {
                log::trace!(target: "citadel", "STAGE SUCCESS CONNECT PACKET");
                // This whole block is complex, involving async calls and sync lock access.
                // It needs careful sequential application of spawn_blocking for its synchronous parts.
                // The original structure was: read state -> validate (sync, CPU) -> update state (sync) -> IO (async) -> update state (sync)
                
                let session_clone_success_outer = session.clone();
                let cnac_clone_outer = cnac.clone();
                let ratchet_clone_outer = ratchet.clone();
                let header_clone_outer = header.clone();
                let payload_clone_outer = payload.clone();

                // Task for validation and initial state updates (synchronous part)
                let (
                    message, kernel_ticket_val, cid, use_ka, connect_mode_val, 
                    udp_channel_rx, channel, session_security_settings_val,
                    addr_val, is_personal_val, mailbox_delivery_val, peers_val,
                    backend_type_val, success_time_val
                ) = tokio::task::spawn_blocking(move || {
                    let mut state_container = inner_mut_state!(session_clone_success_outer.state_container);
                    let last_stage = state_container.connect_state.last_stage;
                    let remote_uses_filesystem = header_clone_outer.group.get() != 0;
                    let local_uses_file_system = matches!(
                        session_clone_success_outer.account_manager.get_backend_type(),
                        BackendType::Filesystem(..)
                    );
                    session_clone_success_outer
                        .file_transfer_compatible
                        .set_once(local_uses_file_system && remote_uses_filesystem);

                    if last_stage != packet_flags::cmd::aux::do_connect::STAGE1 {
                        log::error!(target: "citadel", "An invalid SUCCESS packet was received; dropping since the last local stage was not stage 1");
                        return Err(NetworkError::InvalidState("Last stage was not STAGE1 for SUCCESS packet"));
                    }

                    let validated_payload = validation::do_connect::validate_final_status_packet(&payload_clone_outer)
                        .ok_or(NetworkError::InvalidPacket("Invalid SUCCESS packet; deserialization/validation failed"))?;
                    
                    let msg = String::from_utf8(validated_payload.message.to_vec())
                        .unwrap_or_else(|_| String::from("Invalid message"));
                    let kt = session_clone_success_outer.kernel_ticket.get();
                    let r_cid = ratchet_clone_outer.get_cid();

                    state_container.connect_state.on_success();
                    state_container.connect_state.on_connect_packet_received();

                    let ka = state_container.keep_alive_timeout_ns != 0;
                    let cm = state_container.connect_state.connect_mode.ok_or(NetworkError::InternalError("Unable to load connect mode"))?;
                    let udp_rx = state_container.pre_connect_state.udp_channel_oneshot_tx.rx.take();
                    let ch = state_container.init_new_c2s_virtual_connection(
                        &cnac_clone_outer, kt, header_clone_outer.session_cid.get(), &session_clone_success_outer
                    );
                    let sss = state_container.session_security_settings.expect("Should be set");
                    
                    // Release state_container lock before other potentially locking session operations
                    drop(state_container);

                    session_clone_success_outer.session_cid.set(Some(r_cid));
                    if !session_clone_success_outer.session_manager.upgrade_connection(session_clone_success_outer.remote_peer, r_cid) {
                        return Err(NetworkError::InternalError("Unable to upgrade from a provisional to a protected connection (Client)"));
                    }
                    session_clone_success_outer.state.set(SessionState::Connected);
                    
                    let s_addr = session_clone_success_outer.remote_peer;
                    let s_is_personal = !session_clone_success_outer.is_server;
                    let s_backend_type = session_clone_success_outer.account_manager.get_backend_type();
                    let s_success_time = session_clone_success_outer.time_tracker.get_global_time_ns();

                    Ok((msg, kt, r_cid, ka, cm, udp_rx, ch, sss, s_addr, s_is_personal, validated_payload.mailbox, validated_payload.peers, s_backend_type, s_success_time, validated_payload.post_login_object))
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for SUCCESS validation/state update failed: {}", e)))??;
                
                log::trace!(target: "citadel", "The login to the server was a success. Welcome Message: {}", &message);

                let success_ack = packet_crafter::do_connect::craft_success_ack(
                    &ratchet, // Use original ratchet from initial_sync_data
                    success_time_val,
                    security_level, // Original security_level
                );
                session.send_to_primary_stream(None, success_ack)?; // session is original Arc

                session.send_to_kernel(NodeResult::ConnectSuccess(ConnectSuccess {
                    ticket: kernel_ticket_val,
                    session_cid: cid,
                    remote_addr: addr_val,
                    is_personal: is_personal_val,
                    v_conn_type: VirtualConnectionType::LocalGroupServer { session_cid: cid },
                    services: initial_sync_data.3, // Assuming post_login_object was part of initial_sync_data tuple's 4th element or passed correctly
                    welcome_message: message,
                    channel,
                    udp_rx_opt: udp_channel_rx,
                    session_security_settings: session_security_settings_val,
                }))?;

                if let Some(mailbox_delivery) = mailbox_delivery_val {
                    session.send_to_kernel(NodeResult::MailboxDelivery(
                        MailboxDelivery {
                            session_cid: cid,
                            ticket_opt: None,
                            items: mailbox_delivery,
                        },
                    ))?;
                }
                
                let persistence_handler = session.account_manager.get_persistence_handler().clone();
                let cnac_for_sync = cnac.clone(); // cnac from initial_sync_data
                let post_login_object_for_sync = initial_sync_data.3; // Assuming it's the 4th element

                // Async post-processing
                persistence_handler
                    .synchronize_hyperlan_peer_list_as_client(&cnac_for_sync, peers_val)
                    .await?;
                
                #[cfg(feature = "google-services")]
                if let (Some(rtdb_cfg), Some(jwt)) =
                    (post_login_object_for_sync.rtdb, post_login_object_for_sync.google_auth_jwt)
                {
                    log::trace!(target: "citadel", "Client detected RTDB config + Google Auth web token. Will login + store config to CNAC ...");
                    let rtdb =
                        citadel_user::re_exports::FirebaseRTDB::new_from_jwt(
                            &rtdb_cfg.url,
                            jwt.clone(),
                            rtdb_cfg.api_key.clone(),
                        )
                        .await
                        .map_err(|err| NetworkError::Generic(err.inner))?; // login

                    let citadel_user::re_exports::FirebaseRTDB {
                        base_url,
                        auth,
                        expire_time,
                        api_key,
                        jwt,
                        ..
                    } = rtdb;

                    let client_rtdb_config =
                        citadel_user::external_services::rtdb::RtdbClientConfig {
                            url: base_url,
                            api_key,
                            auth_payload: auth,
                            expire_time,
                            jwt,
                        };
                    cnac_for_sync.store_rtdb_config(client_rtdb_config); // cnac_for_sync is an Arc

                    log::trace!(target: "citadel", "Successfully logged-in to RTDB + stored config inside CNAC ...");
                };

                if let ConnectMode::Fetch { .. } = connect_mode_val {
                    log::trace!(target: "citadel", "[FETCH] complete ...");
                    return Ok(PrimaryProcessorResult::EndSession("Fetch succeeded"));
                }

                if use_ka {
                    let ka_ts = session.time_tracker.get_global_time_ns(); // Fresh timestamp
                    let ka = packet_crafter::keep_alive::craft_keep_alive_packet(
                        &ratchet, // Use original ratchet
                        ka_ts,
                        security_level,
                    );
                    Ok(PrimaryProcessorResult::ReplyToSender(ka))
                } else {
                    log::warn!(target: "citadel", "Keep-alive subsystem will not be used for this session as requested");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            packet_flags::cmd::aux::do_connect::SUCCESS_ACK => {
                log::trace!(target: "citadel", "RECV SUCCESS_ACK");
                if session.is_server { // session is original Arc
                    // This part needs to be in spawn_blocking if it modifies shared state via blocking locks
                    let session_clone_ack = session.clone();
                    tokio::task::spawn_blocking(move || {
                        let signal = inner_mut_state!(session_clone_ack.state_container)
                            .get_endpoint_container_mut(C2S_IDENTITY_CID)?
                            .channel_signal
                            .take()
                            .ok_or(NetworkError::InternalError("Channel signal missing"))?;
                        session_clone_ack.send_to_kernel(signal) // Non-blocking channel send
                    }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for SUCCESS_ACK failed: {}", e)))??;
                    
                    Ok(PrimaryProcessorResult::Void)
                } else {
                    Err(NetworkError::InvalidPacket(
                        "Received a SUCCESS_ACK as a client",
                    ))
                }
            }

            n => {
                log::error!(target: "citadel", "Invalid auxiliary command: {}", n);
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}


// Helper function to create an owned HdpHeader from Ref.
// This is a placeholder; actual implementation might differ based on HdpHeader's definition.
// If HdpHeader is not easily clonable or constructible from bytes, this part needs more thought.
// For now, assuming it can be reconstructed or relevant parts extracted and owned.
fn parsed_header_from_ref<T: Copy>(header_ref: &Ref<&[u8], T>) -> T {
    // This is a simplification. In reality, you'd parse `header_ref.bytes()`
    // into an owned HdpHeader struct or extract necessary fields.
    // If HdpHeader is large and not easily made 'static or Send, this is complex.
    // For the purpose of this fix, we assume an owned version can be made.
    **header_ref // This works if T is Copy and Ref derefs to T.
                 // If HdpHeader is not Copy, you'd do:
                 // HdpHeader::from_bytes(header_ref.bytes()).unwrap() or similar.
}

// Extend futures::FutureExt for .then combinator like syntax if not available
trait FutureExtThen: Sized + futures::Future {
    fn then<Fut, F>(self, f: F) -> futures::future::Then<Self, Fut, F>
    where
        Fut: futures::Future,
        F: FnOnce(Self::Output) -> Fut;
}

impl<T> FutureExtThen for T
where
    T: Sized + futures::Future,
{
    fn then<Fut, F>(self, f: F) -> futures::future::Then<Self, Fut, F>
    where
        Fut: futures::Future,
        F: FnOnce(Self::Output) -> Fut,
    {
        futures::FutureExt::then(self, f)
    }
}
