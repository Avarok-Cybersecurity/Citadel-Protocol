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
    let session = sess_ref.clone();

    let (hr, cnac) = {
        let state_container = inner_state!(session.state_container);
        if !session.is_provisional()
            && state_container.connect_state.last_stage
                != packet_flags::cmd::aux::do_connect::SUCCESS
        {
            log::error!(target: "citadel", "Connect packet received, but the system is not in a provisional state. Dropping");
            return Ok(PrimaryProcessorResult::Void);
        }

        if !state_container.pre_connect_state.success {
            log::error!(target: "citadel", "Connect packet received, but the system has not yet completed the pre-connect stage. Dropping");
            return Ok(PrimaryProcessorResult::Void);
        }

        let hr = return_if_none!(
            get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
            "Could not get proper HR [connect]"
        );
        let cnac = return_if_none!(state_container.cnac.clone(), "CNAC missing");
        (hr, cnac)
    };

    let (header, payload, _, _) = packet.decompose();

    let (header, payload, ratchet) = return_if_none!(
        validation::aead::validate(hr, &header, payload),
        "Unable to validate connect packet"
    );
    let header = header.clone();
    let security_level = header.security_level.into();

    let time_tracker = session.time_tracker;

    let task = async move {
        let session = &session;
        match header.cmd_aux {
            // Node is Bob. Bob gets the encrypted username and password (separately encrypted)
            packet_flags::cmd::aux::do_connect::STAGE0 => {
                log::trace!(target: "citadel", "STAGE 0 CONNECT PACKET");
                let task = {
                    match validation::do_connect::validate_stage0_packet(&cnac, &payload).await {
                        Ok(stage0_packet) => {
                            let mut state_container = inner_mut_state!(session.state_container);
                            let local_uses_file_system = matches!(
                                session.account_manager.get_backend_type(),
                                BackendType::Filesystem(..)
                            );
                            session
                                .file_transfer_compatible
                                .set_once(local_uses_file_system && stage0_packet.uses_filesystem);
                            let cid = ratchet.get_cid();
                            let success_time = session.time_tracker.get_global_time_ns();
                            let addr = session.remote_peer;
                            let is_personal = !session.is_server;
                            let kernel_ticket = session.kernel_ticket.get();

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
                                &cnac,
                                kernel_ticket,
                                header.session_cid.get(),
                                session,
                            );

                            let session_security_settings = state_container
                                .session_security_settings
                                .expect("Should be set");

                            drop(state_container);

                            // Upgrade the connect BEFORE updating the CNAC
                            if !session.session_manager.upgrade_connection(addr, cid) {
                                return Ok(PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection (Server)"));
                            }

                            // register w/ peer layer, get mail in the process
                            let account_manager = session.account_manager.clone();

                            async move {
                                let mailbox_items = session
                                    .session_manager
                                    .register_session_with_peer_layer(cid)
                                    .await?;
                                let peers = account_manager
                                    .get_persistence_handler()
                                    .get_hyperlan_peer_list_as_server(cid)
                                    .await?
                                    .unwrap_or_default();

                                #[cfg(feature = "google-services")]
                                let post_login_object = account_manager
                                    .services_handler()
                                    .on_post_login_serverside(cid)
                                    .await?;
                                #[cfg(not(feature = "google-services"))]
                                let post_login_object =
                                    citadel_user::external_services::ServicesObject::default();

                                let success_packet =
                                    packet_crafter::do_connect::craft_final_status_packet(
                                        &ratchet,
                                        true,
                                        mailbox_items,
                                        post_login_object.clone(),
                                        session.create_welcome_message(cid),
                                        peers,
                                        success_time,
                                        security_level,
                                        session.account_manager.get_backend_type(),
                                    );

                                session.session_cid.set(Some(cid));
                                session.state.set(SessionState::Connected);

                                let cxn_type =
                                    VirtualConnectionType::LocalGroupServer { session_cid: cid };
                                let channel_signal = NodeResult::ConnectSuccess(ConnectSuccess {
                                    ticket: kernel_ticket,
                                    session_cid: cid,
                                    remote_addr: addr,
                                    is_personal,
                                    v_conn_type: cxn_type,
                                    services: post_login_object,
                                    welcome_message: format!("Client {cid} successfully established a connection to the local HyperNode"),
                                    channel,
                                    udp_rx_opt: udp_channel_rx,
                                    session_security_settings,
                                });
                                // safe unwrap. Store the signal
                                inner_mut_state!(session.state_container)
                                    .get_endpoint_container_mut(C2S_IDENTITY_CID)
                                    .as_mut()
                                    .unwrap()
                                    .channel_signal = Some(channel_signal);
                                Ok(PrimaryProcessorResult::ReplyToSender(success_packet))
                            }
                        }

                        Err(err) => {
                            log::error!(target: "citadel", "Error validating stage2 packet. Reason: {err}");
                            let fail_time = time_tracker.get_global_time_ns();

                            //session.state = SessionState::NeedsConnect;
                            let packet = packet_crafter::do_connect::craft_final_status_packet(
                                &ratchet,
                                false,
                                None,
                                ServicesObject::default(),
                                err.to_string(),
                                Vec::new(),
                                fail_time,
                                security_level,
                                session.account_manager.get_backend_type(),
                            );
                            return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                        }
                    }
                };

                task.await
            }

            packet_flags::cmd::aux::do_connect::FAILURE => {
                log::trace!(target: "citadel", "STAGE FAILURE CONNECT PACKET");
                let kernel_ticket = session.kernel_ticket.get();

                let mut state_container = inner_mut_state!(session.state_container);
                if let Some(payload) =
                    validation::do_connect::validate_final_status_packet(&payload)
                {
                    let message = String::from_utf8(payload.message.to_vec())
                        .unwrap_or_else(|_| "Invalid UTF-8 message".to_string());
                    log::error!(target: "citadel", "The server refused to login the user. Reason: {}", &message);
                    let cid = ratchet.get_cid();
                    state_container.connect_state.on_fail();
                    drop(state_container);

                    session.session_cid.set(None);
                    session.state.set(SessionState::NeedsConnect);
                    session.disable_dc_signal();

                    session.send_to_kernel(NodeResult::ConnectFail(ConnectFail {
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
            }

            // Node is finally Alice. The login either failed or succeeded
            packet_flags::cmd::aux::do_connect::SUCCESS => {
                log::trace!(target: "citadel", "STAGE SUCCESS CONNECT PACKET");

                let task = {
                    let mut state_container = inner_mut_state!(session.state_container);
                    let last_stage = state_container.connect_state.last_stage;
                    let remote_uses_filesystem = header.group.get() != 0;
                    let local_uses_file_system = matches!(
                        session.account_manager.get_backend_type(),
                        BackendType::Filesystem(..)
                    );
                    session
                        .file_transfer_compatible
                        .set_once(local_uses_file_system && remote_uses_filesystem);

                    if last_stage == packet_flags::cmd::aux::do_connect::STAGE1 {
                        if let Some(payload) =
                            validation::do_connect::validate_final_status_packet(&payload)
                        {
                            let cnac = cnac.clone();
                            let message = String::from_utf8(payload.message.to_vec())
                                .unwrap_or_else(|_| String::from("Invalid message"));
                            let kernel_ticket = session.kernel_ticket.get();
                            let cid = ratchet.get_cid();

                            state_container.connect_state.on_success();
                            state_container.connect_state.on_connect_packet_received();

                            let use_ka = state_container.keep_alive_timeout_ns != 0;
                            let connect_mode = return_if_none!(
                                state_container.connect_state.connect_mode,
                                "Unable to load connect mode"
                            );
                            let udp_channel_rx = state_container
                                .pre_connect_state
                                .udp_channel_oneshot_tx
                                .rx
                                .take();

                            let channel = state_container.init_new_c2s_virtual_connection(
                                &cnac,
                                kernel_ticket,
                                header.session_cid.get(),
                                session,
                            );
                            let session_security_settings = state_container
                                .session_security_settings
                                .expect("Should be set");
                            std::mem::drop(state_container);

                            session.session_cid.set(Some(cid)); // This makes is_provisional equal to false

                            let addr = session.remote_peer;
                            let is_personal = !session.is_server;

                            // Upgrade the connect BEFORE updating the CNAC
                            if !session
                                .session_manager
                                .upgrade_connection(session.remote_peer, cid)
                            {
                                return Ok(PrimaryProcessorResult::EndSession("Unable to upgrade from a provisional to a protected connection (Client)"));
                            }

                            log::trace!(target: "citadel", "The login to the server was a success. Welcome Message: {}", &message);

                            let _post_login_object = payload.post_login_object.clone();
                            //session.post_quantum = pqc;
                            let cxn_type =
                                VirtualConnectionType::LocalGroupServer { session_cid: cid };
                            let peers = payload.peers;

                            let timestamp = session.time_tracker.get_global_time_ns();

                            let persistence_handler =
                                session.account_manager.get_persistence_handler().clone();
                            //session.session_manager.clear_provisional_tracker(session.kernel_ticket);
                            session.state.set(SessionState::Connected);

                            let success_ack = packet_crafter::do_connect::craft_success_ack(
                                &ratchet,
                                timestamp,
                                security_level,
                            );
                            session.send_to_primary_stream(None, success_ack)?;

                            session.send_to_kernel(NodeResult::ConnectSuccess(ConnectSuccess {
                                ticket: kernel_ticket,
                                session_cid: cid,
                                remote_addr: addr,
                                is_personal,
                                v_conn_type: cxn_type,
                                services: payload.post_login_object,
                                welcome_message: message,
                                channel,
                                udp_rx_opt: udp_channel_rx,
                                session_security_settings,
                            }))?;
                            //finally, if there are any mailbox items, send them to the kernel for processing
                            if let Some(mailbox_delivery) = payload.mailbox {
                                session.send_to_kernel(NodeResult::MailboxDelivery(
                                    MailboxDelivery {
                                        session_cid: cid,
                                        ticket_opt: None,
                                        items: mailbox_delivery,
                                    },
                                ))?;
                            }
                            // TODO: Clean this up to prevent multiple saves
                            async move {
                                persistence_handler
                                    .synchronize_hyperlan_peer_list_as_client(&cnac, peers)
                                    .await?;
                                #[cfg(feature = "google-services")]
                                if let (Some(rtdb_cfg), Some(jwt)) =
                                    (_post_login_object.rtdb, _post_login_object.google_auth_jwt)
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
                                    cnac.store_rtdb_config(client_rtdb_config);

                                    log::trace!(target: "citadel", "Successfully logged-in to RTDB + stored config inside CNAC ...");
                                };

                                if let ConnectMode::Fetch { .. } = connect_mode {
                                    log::trace!(target: "citadel", "[FETCH] complete ...");
                                    // we can end the session now. The ratchets packets have already been sent alongside the connect signal above
                                    return Ok(PrimaryProcessorResult::EndSession(
                                        "Fetch succeeded",
                                    ));
                                }

                                if use_ka {
                                    let ka = packet_crafter::keep_alive::craft_keep_alive_packet(
                                        &ratchet,
                                        timestamp,
                                        security_level,
                                    );
                                    Ok(PrimaryProcessorResult::ReplyToSender(ka))
                                } else {
                                    log::warn!(target: "citadel", "Keep-alive subsystem will not be used for this session as requested");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            }
                        } else {
                            log::error!(target: "citadel", "An invalid SUCCESS packet was received; dropping due to invalid deserialization");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    } else {
                        log::error!(target: "citadel", "An invalid SUCCESS packet was received; dropping since the last local stage was not stage 1");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                task.await
            }

            packet_flags::cmd::aux::do_connect::SUCCESS_ACK => {
                log::trace!(target: "citadel", "RECV SUCCESS_ACK");
                if session.is_server {
                    let signal = inner_mut_state!(session.state_container)
                        .get_endpoint_container_mut(C2S_IDENTITY_CID)?
                        .channel_signal
                        .take()
                        .ok_or(NetworkError::InternalError("Channel signal missing"))?;
                    session.send_to_kernel(signal)?;
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
