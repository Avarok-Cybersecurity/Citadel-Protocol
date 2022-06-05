use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_wire::udp_traversal::targetted_udp_socket_addr::HolePunchedUdpSocket;
use hyxe_wire::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use netbeam::sync::RelativeNodeType;

use crate::constants::HOLE_PUNCH_SYNC_TIME_MULTIPLIER;
use crate::error::NetworkError;
use crate::hdp::hdp_packet::packet_flags::payload_identifiers;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::hdp::misc::udp_internal_interface::{QuicUdpSocketConnector, RawUdpSocketConnector, UdpSplittableTypes};
use crate::hdp::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::hdp::peer::peer_layer::UdpMode;
use crate::hdp::state_container::{VirtualTargetType, StateContainerInner};
use crate::hdp::state_subcontainers::preconnect_state_container::UdpChannelSender;

use super::includes::*;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use hyxe_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use std::sync::atomic::Ordering;
use crate::hdp::packet_processor::raw_primary_packet::ConcurrentProcessorTx;
use hyxe_wire::exports::NewConnection;

/// Handles preconnect packets. Handles the NAT traversal
/// TODO: Cleanup and organize code
pub fn process(session_orig: &HdpSession, packet: HdpPacket, concurrent_processor_tx: &ConcurrentProcessorTx) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_orig.clone();

    if !session.is_provisional() {
        log::error!("Pre-Connect packet received, but the system is not in a provisional state. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let ref session = session;
        let (header_main, payload) = return_if_none!(packet.parse(), "Unable to parse packet");
        let header = header_main;
        let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_preconnect::SYN => {
                log::info!("RECV STAGE SYN PRE_CONNECT PACKET");
                // first make sure the cid isn't already connected

                let account_manager = session.account_manager.clone();
                if let Some(cnac) = account_manager.get_client_by_cid(header.session_cid.get()).await? {
                    let mut state_container = inner_mut_state!(session.state_container);
                    let adjacent_proto_version = header.group.get();

                    let header_if_err_occurs = header.clone();

                    match validation::pre_connect::validate_syn(&cnac, packet, &session.session_manager) {
                        Ok((static_aux_ratchet, transfer, session_security_settings, peer_only_connect_mode, udp_mode, kat, nat_type)) => {
                            session.adjacent_nat_type.set_once(Some(nat_type));
                            // since the SYN's been validated, the CNACs toolset has been updated
                            let new_session_sec_lvl = transfer.security_level;

                            // TODO: prevent logins if versions out of sync. For now, don't
                            if proto_version_out_of_sync(adjacent_proto_version) {
                                log::warn!("\nLocal protocol version: {} | Adjacent protocol version: {} | Versions out of sync; program may not function\n", crate::constants::BUILD_VERSION, adjacent_proto_version);
                            }

                            log::info!("Synchronizing toolsets. UDP mode: {:?}. Session security level: {:?}", udp_mode, new_session_sec_lvl);
                            // TODO: Rate limiting to prevent SYN flooding
                            let timestamp = session.time_tracker.get_global_time_ns();

                            state_container.pre_connect_state.on_packet_received();

                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                            state_container.keep_alive_timeout_ns = kat;

                            let unused_port = if udp_mode == UdpMode::Enabled {
                                state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
                                // we also need to reserve a local socket addr. Since servers are usually globally-reachable, we assume no IP/port translation
                                if inner!(session.primary_stream_quic_conn).is_none() {
                                    // we need to reserve a new UDP socket since we can't use the local bind addr if there are multiple udp-requesting connections to this server
                                    let socket = hyxe_wire::socket_helpers::get_unused_udp_socket_at_bind_ip(session.local_bind_addr.ip())?;
                                    let port = socket.local_addr()?.port();
                                    state_container.pre_connect_state.unused_local_udp_socket = Some(socket);
                                    Some(port)
                                } else {
                                    None
                                }
                            } else { None };

                            // here, we also send the peer's external address to itself
                            // Also, we use the security level that was created on init b/c the other side still uses the static aux ratchet
                            let syn_ack = hdp_packet_crafter::pre_connect::craft_syn_ack(&static_aux_ratchet, transfer, session.local_nat_type.clone(), unused_port, timestamp, security_level);

                            state_container.udp_mode = udp_mode;
                            state_container.cnac = Some(cnac);
                            state_container.session_security_settings = Some(session_security_settings);
                            session.peer_only_connect_protocol.set(Some(peer_only_connect_mode));

                            Ok(PrimaryProcessorResult::ReplyToSender(syn_ack))
                        }

                        Err(err) => {
                            log::error!("Invalid SYN packet received: {:?}", &err);
                            let packet = hdp_packet_crafter::pre_connect::craft_halt(&header_if_err_occurs, err.into_string());
                            Ok(PrimaryProcessorResult::ReplyToSender(packet))
                        }
                    }
                } else {
                    let bad_cid = header.session_cid.get();
                    let error = format!("CID {} is not registered to this node", bad_cid);
                    let packet = hdp_packet_crafter::pre_connect::craft_halt(&*header, &error);
                    return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                }
            }

            packet_flags::cmd::aux::do_preconnect::SYN_ACK => {
                log::info!("RECV STAGE SYN_ACK PRE_CONNECT PACKET");
                let ref cnac = return_if_none!(inner_state!(session.state_container).cnac.clone(), "SESS Cnac not loaded");

                let (stream, new_hyper_ratchet) = {
                    let mut state_container = inner_mut_state!(session.state_container);
                    if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                        // cnac should already be loaded locally
                        let alice_constructor = return_if_none!(state_container.pre_connect_state.constructor.take(), "Alice constructor not loaded");

                        if let Some((new_hyper_ratchet, nat_type, _server_udp_port_opt)) = validation::pre_connect::validate_syn_ack(cnac, alice_constructor, packet) {
                            // The toolset, at this point, has already been updated. The CNAC can be used to
                            //let ref drill = cnac.get_drill_blocking(None)?;
                            session.adjacent_nat_type.set_once(Some(nat_type.clone()));

                            let local_node_type = session.local_node_type;
                            let timestamp = session.time_tracker.get_global_time_ns();
                            //let local_bind_addr = session.local_bind_addr.ip();
                            //let local_bind_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;

                            if state_container.udp_mode == UdpMode::Disabled {
                                let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, timestamp, local_node_type, security_level);
                                state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                                return Ok(PrimaryProcessorResult::ReplyToSender(stage0_preconnect_packet));
                            }

                            // another check. If we are already using a QUIC connection for the primary stream, we don't need to hole-punch.
                            if let Some(quic_conn) = inner_mut!(session.primary_stream_quic_conn).take() {
                                return send_success_as_initiator(get_quic_udp_interface(quic_conn, session.local_bind_addr), &new_hyper_ratchet, session, security_level, cnac, &mut *state_container);
                            }

                            let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, timestamp, local_node_type, security_level);
                            let to_primary_stream = return_if_none!(session.to_primary_stream.clone(), "Primary stream not loaded");
                            to_primary_stream.unbounded_send(stage0_preconnect_packet)?;

                            //let hole_puncher = SingleUDPHolePuncher::new_initiator(session.local_nat_type.clone(), generate_hole_punch_crypt_container(new_hyper_ratchet.clone(), SecurityLevel::LOW), nat_type, local_bind_addr, server_external_addr, server_internal_addr).ok()?;
                            let stream = ReliableOrderedCompatStream::new(to_primary_stream, &mut *state_container, C2S_ENCRYPTION_ONLY, new_hyper_ratchet.clone(), security_level);
                            (stream, new_hyper_ratchet)
                        } else {
                            log::error!("Invalid SYN_ACK");
                            return Ok(PrimaryProcessorResult::Void)
                        }
                    } else {
                        log::error!("Expected stage SYN_ACK, but local state was not valid");
                        return Ok(PrimaryProcessorResult::Void)
                    }
                };

                let ref conn = NetworkEndpoint::register(RelativeNodeType::Initiator, stream).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                log::info!("Initiator created");
                let res = conn.begin_udp_hole_punch(generate_hole_punch_crypt_container(new_hyper_ratchet.clone(), SecurityLevel::LOW, C2S_ENCRYPTION_ONLY)).await;

                match res {
                    Ok(ret) => {
                        log::info!("Initiator finished NAT traversal ...");
                        send_success_as_initiator(get_raw_udp_interface(ret), &new_hyper_ratchet, session, security_level, cnac, &mut *inner_mut_state!(session.state_container))
                    }

                    Err(err) => {
                        log::warn!("Hole punch attempt failed. Will exit session: {:?}", err.to_string());
                        // Note: this currently implies that if NAT traversal fails, the session does not open (which should be the case for C2S connections anyways)
                        Ok(PrimaryProcessorResult::EndSession("UDP NAT traversal failed"))
                    }
                }
            }

            packet_flags::cmd::aux::do_preconnect::STAGE0 => {
                log::info!("RECV STAGE 0 PRE_CONNECT PACKET");

                // At this point, the user's static-key identity has been verified. We can now check the online status to ensure no double-logins
                let ref cnac = return_if_none!(inner_state!(session.state_container).cnac.clone(), "Sess CNAC not loaded");
                let hyper_ratchet = return_if_none!(cnac.get_hyper_ratchet(Some(header.drill_version.get())), "HR version not found");

                let stream = {

                    let mut state_container = inner_mut_state!(session.state_container);
                    if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                        if let Some(_) = validation::pre_connect::validate_stage0(&hyper_ratchet, packet) {

                            let timestamp = session.time_tracker.get_global_time_ns();

                            //let peer_nat_type = return_if_none!(session.adjacent_nat_type.clone(), "adjacent NAT type not loaded");
                            //let peer_accessible = peer_nat_type.predict_external_addr_from_local_bind_port(0).is_some();

                            if state_container.udp_mode == UdpMode::Disabled {
                                // since this node is the server, send a BEGIN CONNECT signal to alice
                                // We have to modify the state to ensure that this node can receive a DO_CONNECT packet
                                state_container.pre_connect_state.success = true;
                                let packet = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                                return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                            } // .. otherwise, continue logic below to punch a hole through the firewall

                            // At this point, UDP mode is enabled and we aren't using QUIC.
                            std::mem::drop(state_container.pre_connect_state.unused_local_udp_socket.take());

                            //let _peer_internal_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;
                            let to_primary_stream = return_if_none!(session.to_primary_stream.clone(), "Primary stream not loaded");

                            let stream = ReliableOrderedCompatStream::new(to_primary_stream, &mut *state_container, C2S_ENCRYPTION_ONLY, hyper_ratchet.clone(), security_level);
                            stream
                        } else {
                            log::error!("Unable to validate stage 0 packet");
                            return Ok(PrimaryProcessorResult::Void)
                        }
                    } else {
                        log::error!("Packet state 0, last stage not 0. Dropping");
                        return Ok(PrimaryProcessorResult::Void)
                    }
                };

                let ref conn = NetworkEndpoint::register(RelativeNodeType::Receiver, stream).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                log::info!("Receiver created");

                let res = conn.begin_udp_hole_punch(generate_hole_punch_crypt_container(hyper_ratchet.clone(), SecurityLevel::LOW, C2S_ENCRYPTION_ONLY)).await;

                match res {
                    Ok(ret) => {
                        handle_success_as_receiver(get_raw_udp_interface(ret), session, cnac, &mut *inner_mut_state!(session.state_container))
                    }

                    Err(err) => {
                        log::info!("Hole punch attempt failed ({}). Will fallback to TCP only mode. Will await for adjacent node to continue exchange", err.to_string());
                        // We await the initiator to choose a method
                        let mut state_container = inner_mut_state!(session.state_container);
                        state_container.udp_mode = UdpMode::Disabled;
                        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                        Ok(PrimaryProcessorResult::Void)
                    }
                }
            }

            // Alice (initiator) sends this to Bob (receiver)
            packet_flags::cmd::aux::do_preconnect::SUCCESS | packet_flags::cmd::aux::do_preconnect::FAILURE => {
                let success = header.cmd_aux == packet_flags::cmd::aux::do_preconnect::SUCCESS;

                if success {
                    log::info!("RECV STAGE SUCCESS PRE CONNECT PACKET");
                } else {
                    log::info!("RECV STAGE FAILURE PRE CONNECT PACKET");
                }

                let timestamp = session.time_tracker.get_global_time_ns();
                let mut state_container = inner_mut_state!(session.state_container);
                let ref cnac = return_if_none!(state_container.cnac.clone(), "Sess CNAC not loaded");
                let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;
                if let Some(hyper_ratchet) = validation::pre_connect::validate_final(cnac, packet) {
                    state_container.pre_connect_state.success = true;
                    if !success {
                        state_container.udp_mode = UdpMode::Disabled;
                    }

                    // if we are using tcp_only, skip the rest and go straight to sending the packet
                    if tcp_only {
                        log::warn!("Received signal to fall-back to TCP only mode");
                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        return Ok(PrimaryProcessorResult::ReplyToSender(begin_connect));
                    }

                    // another check. If we are already using a QUIC connection for the primary stream, AND we are using UDP mode, then this
                    // server node will need to mirror the opposite side and setup a UDP conn internally
                    if state_container.udp_mode == UdpMode::Enabled {
                        if let Some(quic_conn) = inner_mut!(session.primary_stream_quic_conn).take() {
                            log::info!("[Server/QUIC-UDP] Loading ...");
                            let _ = handle_success_as_receiver(get_quic_udp_interface(quic_conn, session.local_bind_addr), session, cnac, &mut *state_container)?;
                        }
                    }

                    // if we aren't using tcp only, and, failed, end the session
                    if !tcp_only && !success {
                        let ticket = state_container.pre_connect_state.ticket.clone().unwrap_or_else(|| session.kernel_ticket.get());
                        std::mem::drop(state_container);
                        //session.needs_close_message.set(false);
                        session.send_to_kernel(NodeResult::ConnectFail(ticket, Some(cnac.get_cid()), "Preconnect stage failed".to_string()))?;
                        Ok(PrimaryProcessorResult::EndSession("Failure packet received"))
                    } else {
                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        Ok(PrimaryProcessorResult::ReplyToSender(begin_connect))
                    }
                } else {
                    log::error!("Unable to validate success packet. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            // the client gets this. The client must now begin the connect process
            packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT => {
                log::info!("RECV STAGE BEGIN_CONNECT PRE CONNECT PACKET");
                let mut state_container = inner_mut_state!(session.state_container);
                let ref cnac = return_if_none!(state_container.cnac.clone(), "Sess CNAC not loaded");

                if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SUCCESS {
                    if let Some(hyper_ratchet) = validation::pre_connect::validate_begin_connect(cnac, packet) {
                        state_container.pre_connect_state.success = true;
                        std::mem::drop(state_container);
                        // now, begin stage 0 connect
                        begin_connect_process(&session, &hyper_ratchet, security_level)
                    } else {
                        log::error!("Unable to validate success_ack packet. Dropping");
                        Ok(PrimaryProcessorResult::Void)
                    }
                } else {
                    log::error!("Last stage is not SUCCESS, yet a BEGIN_CONNECT packet was received. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }

            packet_flags::cmd::aux::do_preconnect::HALT => {
                let message = String::from_utf8(payload.to_vec()).unwrap_or("INVALID UTF-8".into());
                let ticket = session.kernel_ticket.get();
                session.send_to_kernel(NodeResult::ConnectFail(ticket, Some(header.session_cid.get()), message))?;
                //session.needs_close_message.set(false);
                Ok(PrimaryProcessorResult::EndSession("Preconnect signalled to halt"))
            }

            _ => {
                log::error!("Invalid auxiliary command");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(concurrent_processor_tx, task)
}

fn begin_connect_process(session: &HdpSession, hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> Result<PrimaryProcessorResult, NetworkError> {
    // at this point, the session keys have already been re-established. We just need to begin the login stage
    let mut state_container = inner_mut_state!(session.state_container);
    let timestamp = session.time_tracker.get_global_time_ns();
    let proposed_credentials = return_if_none!(state_container.connect_state.proposed_credentials.take(), "Proposed creds not loaded");
    let fcm_keys = session.fcm_keys.clone();

    let stage0_connect_packet = crate::hdp::hdp_packet_crafter::do_connect::craft_stage0_packet(&hyper_ratchet, proposed_credentials, fcm_keys, timestamp, security_level);
    state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
    // we now store the pqc temporarily in the state container
    //session.post_quantum = Some(new_pqc);
    std::mem::drop(state_container);
    session.state.store(SessionState::ConnectionProcess, Ordering::Relaxed);

    log::info!("Successfully sent stage0 connect packet outbound");

    // Keep the session open even though we transitioned from the pre-connect to connect stage
    Ok(PrimaryProcessorResult::ReplyToSender(stage0_connect_packet))
}

fn send_success_as_initiator(udp_splittable: UdpSplittableTypes, hyper_ratchet: &HyperRatchet, session: &HdpSession, security_level: SecurityLevel, cnac: &ClientNetworkAccount, state_container: &mut StateContainerInner) -> Result<PrimaryProcessorResult, NetworkError> {
    let _ = handle_success_as_receiver(udp_splittable, session, cnac, state_container)?;

    let success_packet = hdp_packet_crafter::pre_connect::craft_stage_final(hyper_ratchet, true, false, session.time_tracker.get_global_time_ns(),  security_level);
    Ok(PrimaryProcessorResult::ReplyToSender(success_packet))
}

fn handle_success_as_receiver(udp_splittable: UdpSplittableTypes, session: &HdpSession, cnac: &ClientNetworkAccount, state_container: &mut StateContainerInner) -> Result<PrimaryProcessorResult, NetworkError> {
    let tcp_loaded_alerter_rx = state_container.setup_tcp_alert_if_udp_c2s();
    let peer_addr = udp_splittable.peer_addr();

    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
    state_container.pre_connect_state.on_packet_received();

    // the UDP subsystem will automatically engage at this point
    HdpSession::udp_socket_loader(session.clone(), VirtualTargetType::HyperLANPeerToHyperLANServer(cnac.get_cid()), udp_splittable, peer_addr, session.kernel_ticket.get(), Some(tcp_loaded_alerter_rx));
    // the server will await for the client to send an initiation packeet
    Ok(PrimaryProcessorResult::Void)
}

pub(crate) fn generate_hole_punch_crypt_container(hyper_ratchet: HyperRatchet, security_level: SecurityLevel, target_cid: u64) -> EncryptedConfigContainer {
    let hyper_ratchet_cloned = hyper_ratchet.clone();
    EncryptedConfigContainer::new(move |plaintext| {
        hdp_packet_crafter::hole_punch::generate_packet(&hyper_ratchet, plaintext, security_level, target_cid)
    }, move |packet| {
        hdp_packet_crafter::hole_punch::decrypt_packet(&hyper_ratchet_cloned, packet, security_level)
    })
}

/// Returns the instant in time when the sync_time happens, and the inscribable i64 thereof
pub fn calculate_sync_time(current: i64, header: i64) -> (Instant, i64) {
    let ping = i64::abs(current - header) as u64;
    let delta = HOLE_PUNCH_SYNC_TIME_MULTIPLIER * (ping as f64);
    let delta = delta as i64;
    // we send this timestamp, allowing the other end to begin the hole-punching process once this moment is reached
    let sync_time_ns = current + delta;
    log::info!("Sync time: {}", sync_time_ns);
    let sync_time_instant = Instant::now() + Duration::from_nanos(delta as u64);
    (sync_time_instant, sync_time_ns)
}

fn proto_version_out_of_sync(adjacent_proto_version: u64) -> bool {
    adjacent_proto_version as usize != crate::constants::BUILD_VERSION
}

fn get_raw_udp_interface(socket: HolePunchedUdpSocket) -> UdpSplittableTypes {
    log::info!("Will use Raw UDP for UDP transmission");
    UdpSplittableTypes::Raw(RawUdpSocketConnector::new(socket.socket, socket.addr.receive_address))
}

fn get_quic_udp_interface(quic_conn: NewConnection, local_addr: SocketAddr) -> UdpSplittableTypes {
    log::info!("Will use QUIC UDP for UDP transmission");
    UdpSplittableTypes::QUIC(QuicUdpSocketConnector::new(quic_conn, local_addr))
}