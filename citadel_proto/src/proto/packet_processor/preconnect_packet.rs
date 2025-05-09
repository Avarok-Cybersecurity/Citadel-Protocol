//! Preconnect packet processor for the Citadel Protocol
//!
//! This module handles the initial connection establishment and NAT traversal process
//! between peers in the Citadel Protocol network. It implements the preconnect handshake
//! which establishes secure communication channels between nodes.
//!
//! # Features
//!
//! - NAT traversal and hole punching for P2P connections
//! - Protocol version compatibility checking
//! - Session state validation and management
//! - Security level negotiation
//! - UDP and QUIC transport support
//! - Cryptographic ratchet initialization
//!
//! # Important Notes
//!
//! - The preconnect process must complete before any other protocol operations
//! - NAT traversal uses configurable STUN servers for hole punching
//! - Protocol version mismatches are currently warned but not enforced
//! - Sessions must be in provisional state to process preconnect packets
//!
//! # Related Components
//!
//! - `StateContainer`: Manages connection state during preconnect
//! - `StackedRatchet`: Provides cryptographic primitives for secure channels
//! - `UdpHolePuncher`: Handles NAT traversal operations
//! - `SessionManager`: Tracks active protocol sessions

use citadel_crypt::endpoint_crypto_container::AssociatedSecurityLevel;
use citadel_crypt::ratchets::Ratchet;
use citadel_wire::udp_traversal::hole_punched_socket::HolePunchedUdpSocket;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use netbeam::sync::RelativeNodeType;

use crate::constants::HOLE_PUNCH_SYNC_TIME_MULTIPLIER;
use crate::error::NetworkError;
use crate::proto::misc::udp_internal_interface::{
    QuicUdpSocketConnector, RawUdpSocketConnector, UdpSplittableTypes,
};
use crate::proto::packet::packet_flags::payload_identifiers;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::state_container::{StateContainerInner, VirtualTargetType};
use citadel_types::proto::UdpMode;

use super::includes::*;
use crate::proto::node_result::ConnectFail;
use crate::proto::packet_processor::primary_group_packet::get_orientation_safe_ratchet;
use crate::proto::state_subcontainers::preconnect_state_container::UdpChannelSender;
use citadel_wire::exports::Connection;
use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;

/// Handles preconnect packets. Handles the NAT traversal
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_orig.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_preconnect<R: Ratchet>(
    session_orig: &CitadelSession<R>,
    packet: HdpPacket,
    header_entropy_bank_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_orig.clone();

    if !session.is_provisional() {
        log::error!(target: "citadel", "Pre-Connect packet received, but the system is not in a provisional state. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let session = &session;
        let (header_main, payload) = return_if_none!(packet.parse(), "Unable to parse packet");
        let header = header_main;
        let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_preconnect::SYN => {
                log::trace!(target: "citadel", "RECV STAGE SYN PRE_CONNECT PACKET");
                // TODO: prevent logins if semvers out of sync. For now, don't
                let adjacent_proto_version = header.protocol_version.get();
                if proto_version_out_of_sync(adjacent_proto_version)? {
                    log::warn!(target: "citadel", "\nLocal protocol version: {} | Adjacent protocol version: {} | Versions out of sync; program may not function\n", *crate::constants::PROTOCOL_VERSION, adjacent_proto_version);
                    // TODO: protocol translations for inter-version compatibility
                }
                // first make sure the cid isn't already connected
                let session_already_active = session
                    .session_manager
                    .session_active(header.session_cid.get());
                let account_manager = session.account_manager.clone();
                let header_if_err_occurs = header.clone();

                let error = |err: NetworkError| {
                    let packet = packet_crafter::pre_connect::craft_halt(
                        &header_if_err_occurs,
                        err.into_string(),
                    );
                    Ok(PrimaryProcessorResult::ReplyToSender(packet))
                };

                if session_already_active {
                    return error(NetworkError::InvalidRequest("Session Already Connected"));
                }

                if let Some(cnac) = account_manager
                    .get_client_by_cid(header.session_cid.get())
                    .await?
                {
                    let mut state_container = inner_mut_state!(session.state_container);
                    state_container
                        .store_session_password(C2S_IDENTITY_CID, session.session_password.clone());
                    match validation::pre_connect::validate_syn(
                        &cnac,
                        packet,
                        &session.session_manager,
                        &session.session_password,
                    ) {
                        Ok((
                            static_aux_ratchet,
                            transfer,
                            session_security_settings,
                            peer_only_connect_mode,
                            udp_mode,
                            kat,
                            nat_type,
                            new_ratchet,
                        )) => {
                            session.adjacent_nat_type.set_once(Some(nat_type));
                            state_container.pre_connect_state.generated_ratchet = Some(new_ratchet);
                            // since the SYN's been validated, the CNACs toolset has been updated
                            let new_session_sec_lvl = transfer.security_level();

                            log::trace!(target: "citadel", "Synchronizing toolsets. UDP mode: {:?}. Session security level: {:?}", udp_mode, new_session_sec_lvl);
                            // TODO: Rate limiting to prevent SYN flooding
                            let timestamp = session.time_tracker.get_global_time_ns();

                            state_container.pre_connect_state.on_packet_received();

                            state_container.pre_connect_state.last_stage =
                                packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                            state_container.keep_alive_timeout_ns = kat;

                            // here, we also send the peer's external address to itself
                            // Also, we use the security level that was created on init b/c the other side still uses the static aux ratchet
                            let syn_ack = packet_crafter::pre_connect::craft_syn_ack(
                                &static_aux_ratchet,
                                transfer,
                                session.local_nat_type.clone(),
                                timestamp,
                                security_level,
                            );

                            state_container.udp_mode = udp_mode;
                            state_container.cnac = Some(cnac);
                            state_container.session_security_settings =
                                Some(session_security_settings);
                            session
                                .peer_only_connect_protocol
                                .set(Some(peer_only_connect_mode));

                            Ok(PrimaryProcessorResult::ReplyToSender(syn_ack))
                        }

                        Err(err) => {
                            log::error!(target: "citadel", "Invalid SYN packet received: {:?}", &err);
                            error(err)
                        }
                    }
                } else {
                    let bad_cid = header.session_cid.get();
                    let error = format!("CID {bad_cid} is not registered to this node");
                    let packet = packet_crafter::pre_connect::craft_halt(&header, error);
                    Ok(PrimaryProcessorResult::ReplyToSender(packet))
                }
            }

            packet_flags::cmd::aux::do_preconnect::SYN_ACK => {
                log::trace!(target: "citadel", "RECV STAGE SYN_ACK PRE_CONNECT PACKET");
                let cnac = &(return_if_none!(
                    inner_state!(session.state_container).cnac.clone(),
                    "SESS Cnac not loaded"
                ));
                let session_cid = header.session_cid.get();

                let (stream, new_ratchet) = {
                    let mut state_container = inner_mut_state!(session.state_container);
                    if state_container.pre_connect_state.last_stage
                        == packet_flags::cmd::aux::do_preconnect::SYN_ACK
                    {
                        // cnac should already be loaded locally
                        let alice_constructor = return_if_none!(
                            state_container.pre_connect_state.constructor.take(),
                            "Alice constructor not loaded"
                        );
                        let session_cid = header.session_cid.get();
                        if let Some((new_ratchet, nat_type)) =
                            validation::pre_connect::validate_syn_ack(
                                &session.session_password,
                                cnac,
                                alice_constructor,
                                packet,
                            )
                        {
                            session.adjacent_nat_type.set_once(Some(nat_type));
                            state_container.pre_connect_state.generated_ratchet =
                                Some(new_ratchet.clone());

                            let local_node_type = session.local_node_type;
                            let timestamp = session.time_tracker.get_global_time_ns();

                            if state_container.udp_mode == UdpMode::Disabled {
                                let stage0_preconnect_packet =
                                    packet_crafter::pre_connect::craft_stage0(
                                        &new_ratchet,
                                        timestamp,
                                        local_node_type,
                                        security_level,
                                    );
                                state_container.pre_connect_state.last_stage =
                                    packet_flags::cmd::aux::do_preconnect::SUCCESS;
                                return Ok(PrimaryProcessorResult::ReplyToSender(
                                    stage0_preconnect_packet,
                                ));
                            }

                            // another check. If we are already using a QUIC connection for the primary stream, we don't need to hole-punch.
                            if let Some(quic_conn) =
                                inner_mut!(session.primary_stream_quic_conn).take()
                            {
                                log::trace!(target: "citadel", "Skipping NAT traversal since QUIC is enabled for this session");
                                return send_success_as_initiator(
                                    Some(get_quic_udp_interface(
                                        quic_conn,
                                        session.local_bind_addr,
                                    )),
                                    &new_ratchet,
                                    session,
                                    security_level,
                                    session_cid,
                                    &mut state_container,
                                );
                            }

                            let stage0_preconnect_packet =
                                packet_crafter::pre_connect::craft_stage0(
                                    &new_ratchet,
                                    timestamp,
                                    local_node_type,
                                    security_level,
                                );
                            let to_primary_stream = return_if_none!(
                                session.to_primary_stream.clone(),
                                "Primary stream not loaded"
                            );
                            to_primary_stream.unbounded_send(stage0_preconnect_packet)?;

                            let stream = ReliableOrderedCompatStream::<R>::new(
                                to_primary_stream,
                                &mut state_container,
                                C2S_IDENTITY_CID,
                                new_ratchet.clone(),
                                security_level,
                            );
                            (stream, new_ratchet)
                        } else {
                            log::error!(target: "citadel", "Invalid SYN_ACK");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    } else {
                        log::error!(target: "citadel", "Expected stage SYN_ACK, but local state was not valid");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                let conn = &(NetworkEndpoint::register(RelativeNodeType::Initiator, stream)
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))?);
                log::trace!(target: "citadel", "Initiator created");
                let stun_servers = session.stun_servers.clone();
                let res = conn
                    .begin_udp_hole_punch(generate_hole_punch_crypt_container(
                        new_ratchet.clone(),
                        SecurityLevel::Standard,
                        C2S_IDENTITY_CID,
                        stun_servers,
                    ))
                    .await;

                match res {
                    Ok(ret) => {
                        log::trace!(target: "citadel", "Initiator finished NAT traversal ...");
                        send_success_as_initiator(
                            Some(get_raw_udp_interface(ret)),
                            &new_ratchet,
                            session,
                            security_level,
                            session_cid,
                            &mut inner_mut_state!(session.state_container),
                        )
                    }

                    Err(err) => {
                        log::warn!(target: "citadel", "Hole punch attempt failed {:?}", err.to_string());
                        send_success_as_initiator(
                            None,
                            &new_ratchet,
                            session,
                            security_level,
                            session_cid,
                            &mut inner_mut_state!(session.state_container),
                        )
                    }
                }
            }

            packet_flags::cmd::aux::do_preconnect::STAGE0 => {
                log::trace!(target: "citadel", "RECV STAGE 0 PRE_CONNECT PACKET");

                let session_cid = header.session_cid.get();
                let (ratchet, stream) = {
                    let mut state_container = inner_mut_state!(session.state_container);
                    // At this point, the user's static-key identity has been verified. We can now check the online status to ensure no double-logins
                    let ratchet = return_if_none!(
                        get_orientation_safe_ratchet(
                            header.entropy_bank_version.get(),
                            &state_container,
                            None
                        ),
                        "HR version not found"
                    );

                    if state_container.pre_connect_state.last_stage
                        == packet_flags::cmd::aux::do_preconnect::SYN_ACK
                    {
                        if validation::pre_connect::validate_stage0(&ratchet, packet).is_some() {
                            let timestamp = session.time_tracker.get_global_time_ns();

                            //let peer_nat_type = return_if_none!(session.adjacent_nat_type.clone(), "adjacent NAT type not loaded");
                            //let peer_accessible = peer_nat_type.predict_external_addr_from_local_bind_port(0).is_some();

                            if state_container.udp_mode == UdpMode::Disabled {
                                // since this node is the server, send a BEGIN CONNECT signal to alice
                                // We have to modify the state to ensure that this node can receive a DO_CONNECT packet
                                state_container.pre_connect_state.success = true;
                                let packet = packet_crafter::pre_connect::craft_begin_connect(
                                    &ratchet,
                                    timestamp,
                                    security_level,
                                );
                                return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                            } // .. otherwise, continue logic below to punch a hole through the firewall

                            //let _peer_internal_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;
                            let to_primary_stream = return_if_none!(
                                session.to_primary_stream.clone(),
                                "Primary stream not loaded"
                            );

                            let stream = ReliableOrderedCompatStream::<R>::new(
                                to_primary_stream,
                                &mut state_container,
                                C2S_IDENTITY_CID,
                                ratchet.clone(),
                                security_level,
                            );
                            (ratchet, stream)
                        } else {
                            log::error!(target: "citadel", "Unable to validate stage 0 packet");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    } else {
                        log::error!(target: "citadel", "Packet state 0, last stage not 0. Dropping");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                };

                let conn = &(NetworkEndpoint::register(RelativeNodeType::Receiver, stream)
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))?);
                log::trace!(target: "citadel", "Receiver created");
                let stun_servers = session.stun_servers.clone();
                let res = conn
                    .begin_udp_hole_punch(generate_hole_punch_crypt_container(
                        ratchet.clone(),
                        SecurityLevel::Standard,
                        C2S_IDENTITY_CID,
                        stun_servers,
                    ))
                    .await;

                match res {
                    Ok(ret) => handle_success_as_receiver(
                        Some(get_raw_udp_interface(ret)),
                        session,
                        session_cid,
                        &mut inner_mut_state!(session.state_container),
                    ),

                    Err(err) => {
                        log::warn!(target: "citadel", "Hole punch attempt failed ({err}). Will fallback to TCP only mode. Will await for adjacent node to continue exchange");
                        // We await the initiator to choose a method
                        let mut state_container = inner_mut_state!(session.state_container);
                        state_container.udp_mode = UdpMode::Disabled;
                        state_container.pre_connect_state.last_stage =
                            packet_flags::cmd::aux::do_preconnect::SUCCESS;
                        Ok(PrimaryProcessorResult::Void)
                    }
                }
            }

            // Alice (initiator) sends this to Bob (receiver)
            packet_flags::cmd::aux::do_preconnect::SUCCESS
            | packet_flags::cmd::aux::do_preconnect::FAILURE => {
                let success = header.cmd_aux == packet_flags::cmd::aux::do_preconnect::SUCCESS;

                if success {
                    log::trace!(target: "citadel", "RECV STAGE SUCCESS PRE CONNECT PACKET");
                } else {
                    log::trace!(target: "citadel", "RECV STAGE FAILURE PRE CONNECT PACKET");
                }

                let timestamp = session.time_tracker.get_global_time_ns();
                let mut state_container = inner_mut_state!(session.state_container);
                let hr = return_if_none!(
                    get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
                    "Could not get proper HR [preconnect0]"
                );
                let cnac = &(return_if_none!(state_container.cnac.clone(), "Sess CNAC not loaded"));
                let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;
                let (header, packet, ..) = packet.decompose();
                if let Some((header, _, ratchet)) = validation::aead::validate(hr, &header, packet)
                {
                    state_container.pre_connect_state.success = true;
                    if !success {
                        state_container.udp_mode = UdpMode::Disabled;
                    }

                    // if we are using tcp_only, skip the rest and go straight to sending the packet
                    if tcp_only {
                        log::warn!(target: "citadel", "Received signal to fall-back to TCP only mode");
                        let begin_connect = packet_crafter::pre_connect::craft_begin_connect(
                            &ratchet,
                            timestamp,
                            security_level,
                        );
                        return Ok(PrimaryProcessorResult::ReplyToSender(begin_connect));
                    }

                    // another check. If we are already using a QUIC connection for the primary stream, AND we are using UDP mode, then this
                    // server node will need to mirror the opposite side and setup a UDP conn internally
                    if state_container.udp_mode == UdpMode::Enabled {
                        if let Some(quic_conn) = inner_mut!(session.primary_stream_quic_conn).take()
                        {
                            log::trace!(target: "citadel", "[Server/QUIC-UDP] Loading ...");
                            let _ = handle_success_as_receiver(
                                Some(get_quic_udp_interface(quic_conn, session.local_bind_addr)),
                                session,
                                header.session_cid.get(),
                                &mut state_container,
                            )?;
                        }
                    }

                    // if we aren't using tcp only, and, failed, end the session
                    if !tcp_only && !success {
                        let ticket = state_container
                            .pre_connect_state
                            .ticket
                            .unwrap_or_else(|| session.kernel_ticket.get());
                        drop(state_container);
                        //session.needs_close_message.set(false);
                        session.send_to_kernel(NodeResult::ConnectFail(ConnectFail {
                            ticket,
                            cid_opt: Some(cnac.get_cid()),
                            error_message: "Preconnect stage failed".to_string(),
                        }))?;
                        Ok(PrimaryProcessorResult::EndSession(
                            "Failure packet received",
                        ))
                    } else {
                        let begin_connect = packet_crafter::pre_connect::craft_begin_connect(
                            &ratchet,
                            timestamp,
                            security_level,
                        );
                        Ok(PrimaryProcessorResult::ReplyToSender(begin_connect))
                    }
                } else {
                    log::error!(target: "citadel", "Unable to validate success packet. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            // the client gets this. The client must now begin the connect process
            packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT => {
                log::trace!(target: "citadel", "RECV STAGE BEGIN_CONNECT PRE_CONNECT PACKET");
                let mut state_container = inner_mut_state!(session.state_container);
                let hr = return_if_none!(
                    get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
                    "Could not get proper HR [preconnect1]"
                );

                if state_container.pre_connect_state.last_stage
                    == packet_flags::cmd::aux::do_preconnect::SUCCESS
                {
                    let (header, payload, _, _) = packet.decompose();
                    if let Some((_, _, ratchet)) = validation::aead::validate(hr, &header, payload)
                    {
                        state_container.pre_connect_state.success = true;
                        std::mem::drop(state_container);
                        // now, begin stage 0 connect
                        begin_connect_process(session, &ratchet, security_level)
                    } else {
                        log::error!(target: "citadel", "Unable to validate success_ack packet. Dropping");
                        Ok(PrimaryProcessorResult::Void)
                    }
                } else {
                    log::error!(target: "citadel", "Last stage is not SUCCESS, yet a BEGIN_CONNECT packet was received. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            packet_flags::cmd::aux::do_preconnect::HALT => {
                let message =
                    String::from_utf8(payload.to_vec()).unwrap_or_else(|_| "INVALID UTF-8".into());
                let ticket = session.kernel_ticket.get();
                session.send_to_kernel(NodeResult::ConnectFail(ConnectFail {
                    ticket,
                    cid_opt: Some(header.session_cid.get()),
                    error_message: message,
                }))?;
                //session.needs_close_message.set(false);
                Ok(PrimaryProcessorResult::EndSession(
                    "Preconnect signalled to halt",
                ))
            }

            _ => {
                log::error!(target: "citadel", "Invalid auxiliary command");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}

fn begin_connect_process<R: Ratchet>(
    session: &CitadelSession<R>,
    ratchet: &R,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    // at this point, the session keys have already been re-established. We just need to begin the login stage
    let mut state_container = inner_mut_state!(session.state_container);
    let timestamp = session.time_tracker.get_global_time_ns();
    let proposed_credentials = return_if_none!(
        state_container.connect_state.proposed_credentials.take(),
        "Proposed creds not loaded"
    );

    let stage0_connect_packet = crate::proto::packet_crafter::do_connect::craft_stage0_packet(
        ratchet,
        proposed_credentials,
        timestamp,
        security_level,
        session.account_manager.get_backend_type(),
    );
    state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
    // we now store the pqc temporarily in the state container
    //session.post_quantum = Some(new_pqc);
    std::mem::drop(state_container);
    session.state.set(SessionState::ConnectionProcess);

    log::trace!(target: "citadel", "Successfully sent stage0 connect packet outbound");

    // Keep the session open even though we transitioned from the pre-connect to connect stage
    Ok(PrimaryProcessorResult::ReplyToSender(stage0_connect_packet))
}

fn send_success_as_initiator<R: Ratchet>(
    udp_splittable: Option<UdpSplittableTypes>,
    ratchet: &R,
    session: &CitadelSession<R>,
    security_level: SecurityLevel,
    session_cid: u64,
    state_container: &mut StateContainerInner<R>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let _ = handle_success_as_receiver(udp_splittable, session, session_cid, state_container)?;

    let success_packet = packet_crafter::pre_connect::craft_stage_final(
        ratchet,
        true,
        false,
        session.time_tracker.get_global_time_ns(),
        security_level,
    );
    Ok(PrimaryProcessorResult::ReplyToSender(success_packet))
}

fn handle_success_as_receiver<R: Ratchet>(
    udp_splittable: Option<UdpSplittableTypes>,
    session: &CitadelSession<R>,
    session_cid: u64,
    state_container: &mut StateContainerInner<R>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let tcp_loaded_alerter_rx = state_container.setup_tcp_alert_if_udp_c2s();

    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
    state_container.pre_connect_state.on_packet_received();

    if state_container
        .pre_connect_state
        .udp_channel_oneshot_tx
        .tx
        .is_none()
    {
        // TODO ensure this exists BEFORE udp socket loading
        state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
    }

    if let Some(udp_splittable) = udp_splittable {
        let peer_addr = udp_splittable.peer_addr();
        // the UDP subsystem will automatically engage at this point
        if state_container.udp_mode == UdpMode::Enabled {
            CitadelSession::udp_socket_loader(
                session.clone(),
                VirtualTargetType::LocalGroupServer { session_cid },
                udp_splittable,
                peer_addr,
                session.kernel_ticket.get(),
                Some(tcp_loaded_alerter_rx),
            );
        }
    } else {
        log::warn!(target: "citadel", "No UDP splittable was specified. UdpMode: {:?}", state_container.udp_mode);
    }
    // the server will await for the client to send an initiation packet
    Ok(PrimaryProcessorResult::Void)
}

pub(crate) fn generate_hole_punch_crypt_container<R: Ratchet>(
    ratchet: R,
    security_level: SecurityLevel,
    target_cid: u64,
    stun_servers: Option<Vec<String>>,
) -> HolePunchConfigContainer {
    let ratchet_cloned = ratchet.clone();

    HolePunchConfigContainer::new(
        move |plaintext| {
            packet_crafter::hole_punch::generate_packet(
                &ratchet,
                plaintext,
                security_level,
                target_cid,
            )
        },
        move |packet| {
            packet_crafter::hole_punch::decrypt_packet(&ratchet_cloned, packet, security_level)
        },
        stun_servers,
    )
}

/// Returns the instant in time when the sync_time happens, and the inscribable i64 thereof
pub fn calculate_sync_time(current: i64, header: i64) -> (Instant, i64) {
    let ping = i64::abs(current - header) as u64;
    let delta = HOLE_PUNCH_SYNC_TIME_MULTIPLIER * (ping as f64);
    let delta = delta as i64;
    // we send this timestamp, allowing the other end to begin the hole-punching process once this moment is reached
    let sync_time_ns = current + delta;
    log::trace!(target: "citadel", "Sync time: {}", sync_time_ns);
    let sync_time_instant = Instant::now() + Duration::from_nanos(delta as u64);
    (sync_time_instant, sync_time_ns)
}

fn proto_version_out_of_sync(adjacent_proto_version: u32) -> Result<bool, NetworkError> {
    use embedded_semver::Semver;
    match Semver::from_u32(adjacent_proto_version) {
        Ok(their_version) => {
            // if either major or minor releases are not equal, assume breaking change
            Ok(
                their_version.major != crate::constants::MAJOR_VERSION as usize
                    || their_version.minor != crate::constants::MINOR_VERSION as usize,
            )
        }

        Err(_) => Err(NetworkError::InvalidRequest(
            "Unable to parse incoming protocol semver",
        )),
    }
}

fn get_raw_udp_interface(socket: HolePunchedUdpSocket) -> UdpSplittableTypes {
    log::trace!(target: "citadel", "Will use Raw UDP for UDP transmission");
    let send_addr = socket.addr.send_address;
    UdpSplittableTypes::Raw(RawUdpSocketConnector::new(socket.into_socket(), send_addr))
}

fn get_quic_udp_interface(quic_conn: Connection, local_addr: SocketAddr) -> UdpSplittableTypes {
    log::trace!(target: "citadel", "Will use QUIC UDP for UDP transmission");
    UdpSplittableTypes::Quic(QuicUdpSocketConnector::new(quic_conn, local_addr))
}

#[cfg(test)]
mod tests {
    use crate::constants::PROTOCOL_VERSION;
    use crate::proto::packet_processor::preconnect_packet::proto_version_out_of_sync;

    #[test]
    fn test_good_version() {
        let our_version = embedded_semver::Semver::from_u32(*PROTOCOL_VERSION).unwrap();
        for shift in 1..3 {
            let their_version = embedded_semver::Semver::new(
                our_version.major,
                our_version.minor,
                our_version.patch + shift,
            );
            assert!(!proto_version_out_of_sync(their_version.to_u32().unwrap()).unwrap())
        }
    }

    #[test]
    fn test_bad_major_version() {
        let our_version = embedded_semver::Semver::from_u32(*PROTOCOL_VERSION).unwrap();
        for shift in 1..3 {
            let their_version = embedded_semver::Semver::new(
                our_version.major + shift,
                our_version.minor,
                our_version.patch,
            );
            assert!(proto_version_out_of_sync(their_version.to_u32().unwrap()).unwrap())
        }
    }

    #[test]
    fn test_bad_minor_version() {
        let our_version = embedded_semver::Semver::from_u32(*PROTOCOL_VERSION).unwrap();
        for shift in 1..3 {
            let their_version = embedded_semver::Semver::new(
                our_version.major,
                our_version.minor + shift,
                our_version.patch,
            );
            assert!(proto_version_out_of_sync(their_version.to_u32().unwrap()).unwrap())
        }
    }

    #[test]
    fn test_bad_parse() {
        assert!(proto_version_out_of_sync(u32::MAX).is_err());
    }
}
