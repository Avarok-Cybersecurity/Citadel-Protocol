use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use hyxe_nat::udp_traversal::linear::RelativeNodeType;

use crate::constants::HOLE_PUNCH_SYNC_TIME_MULTIPLIER;

use super::includes::*;
use hyxe_nat::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hdp::hdp_packet::packet_flags::payload_identifiers;
use crate::hdp::state_container::VirtualTargetType;
use crate::hdp::peer::peer_layer::UdpMode;
use crate::hdp::state_subcontainers::preconnect_state_container::UdpChannelSender;
use hyxe_nat::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use crate::hdp::peer::hole_punch_compat_sink_stream::HolePunchCompatStream;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use tokio::net::UdpSocket;
use crate::hdp::misc::udp_internal_interface::{RawUdpSocketConnector, QuicUdpSocketConnector, UdpSplittableTypes};

/// Handles preconnect packets. Handles the NAT traversal
/// TODO: Note to future programmers. This source file is not the cleanest, and in my opinion the dirtiest file in the entire codebase.
/// This will NEED to be refactored. It's also buggy in some cases. For 99% of cases (100% for TCP ONLY, which is now the default), it does the job though
pub async fn process(session_orig: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = session_orig;

    if !session.is_provisional() {
        log::error!("Pre-Connect packet received, but the system is not in a provisional state. Dropping");
        return PrimaryProcessorResult::Void;
    }

    let (header_main, payload) = packet.parse()?;
    let header = &header_main;
    let security_level = header.security_level.into();

    match header.cmd_aux {
        packet_flags::cmd::aux::do_preconnect::SYN => {
            log::info!("RECV STAGE SYN PRE_CONNECT PACKET");
            // first make sure the cid isn't already connected

            let account_manager = session.account_manager.clone();
            if let Some(cnac) = account_manager.get_client_by_cid(header.session_cid.get()).await? {
                let mut state_container = inner_mut!(session.state_container);
                let adjacent_proto_version = header.group.get();

                let header_if_err_occurs = header_main.clone();

                match validation::pre_connect::validate_syn(&cnac, packet, &session.session_manager) {
                    Ok((static_aux_ratchet, transfer, session_security_settings, peer_only_connect_mode, udp_mode, kat, nat_type, peer_listener_internal_addr)) => {
                        session.adjacent_nat_type.set_once(Some(nat_type));
                        session.implicated_user_p2p_internal_listener_addr.set_once(Some(peer_listener_internal_addr));
                        // since the SYN's been validated, the CNACs toolset has been updated
                        let new_session_sec_lvl = transfer.security_level;

                        // TODO: prevent logins if versions out of sync. For now, don't
                        if proto_version_out_of_sync(adjacent_proto_version) {
                            log::warn!("\nLocal protocol version: {} | Adjacent protocol version: {} | Versions out of sync; program may not function\n", crate::constants::BUILD_VERSION, adjacent_proto_version);
                        }

                        log::info!("Synchronizing toolsets. UDP mode: {:?}. Session security level: {:?}", udp_mode, new_session_sec_lvl);
                        // TODO: Rate limiting to prevent SYN flooding
                        let timestamp = session.time_tracker.get_global_time_ns();

                        // here, we also send the peer's external address to itself
                        // Also, we use the security level that was created on init b/c the other side still uses the static aux ratchet
                        let syn_ack = hdp_packet_crafter::pre_connect::craft_syn_ack(&static_aux_ratchet, transfer, session.local_nat_type.clone(), timestamp, security_level);

                        state_container.pre_connect_state.on_packet_received();

                        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                        state_container.keep_alive_timeout_ns = kat;

                        if udp_mode == UdpMode::Enabled {
                            state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
                        }

                        std::mem::drop(state_container);

                        session.udp_mode.set(udp_mode);
                        session.cnac.set(Some(cnac));
                        session.security_settings.set(Some(session_security_settings));
                        session.peer_only_connect_protocol.set(Some(peer_only_connect_mode));

                        PrimaryProcessorResult::ReplyToSender(syn_ack)
                    }

                    Err(err) => {
                        log::error!("Invalid SYN packet received: {:?}", &err);
                        let packet = hdp_packet_crafter::pre_connect::craft_halt(&header_if_err_occurs, err.into_string());
                        PrimaryProcessorResult::ReplyToSender(packet)
                    }
                }
            } else {
                let bad_cid = header.session_cid.get();
                let error = format!("CID {} is not registered to this node", bad_cid);
                let packet = hdp_packet_crafter::pre_connect::craft_halt(header, &error);
                return PrimaryProcessorResult::ReplyToSender(packet);
            }
        }

        packet_flags::cmd::aux::do_preconnect::SYN_ACK => {
            log::info!("RECV STAGE SYN_ACK PRE_CONNECT PACKET");
            let udp_mode = session.udp_mode.get();
            // we now shadow the security_level above, and ensure all further packets use the desired default
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                // cnac should already be loaded locally
                let ref cnac = session.cnac.get()?;
                let alice_constructor = state_container.pre_connect_state.constructor.take()?;

                if let Some((new_hyper_ratchet, nat_type)) = validation::pre_connect::validate_syn_ack(cnac, alice_constructor, packet) {
                    // The toolset, at this point, has already been updated. The CNAC can be used to
                    //let ref drill = cnac.get_drill_blocking(None)?;
                    session.adjacent_nat_type.set_once(Some(nat_type.clone()));

                    let local_node_type = session.local_node_type;
                    let timestamp = session.time_tracker.get_global_time_ns();
                    //let local_bind_addr = session.local_bind_addr.ip();
                    let local_bind_addr = session.local_bind_addr;
                    //let local_bind_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;
                    let server_external_addr = session.remote_peer;

                    if udp_mode == UdpMode::Disabled {
                        let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, timestamp, local_node_type, security_level);
                        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                        return PrimaryProcessorResult::ReplyToSender(stage0_preconnect_packet);
                    }

                    let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, timestamp, local_node_type, security_level);
                    let to_primary_stream = session.to_primary_stream.clone()?;
                    to_primary_stream.unbounded_send(stage0_preconnect_packet)?;

                    //let hole_puncher = SingleUDPHolePuncher::new_initiator(session.local_nat_type.clone(), generate_hole_punch_crypt_container(new_hyper_ratchet.clone(), SecurityLevel::LOW), nat_type, local_bind_addr, server_external_addr, server_internal_addr).ok()?;
                    let conn = HolePunchCompatStream::new(to_primary_stream, &mut *state_container, server_external_addr, local_bind_addr, C2S_ENCRYPTION_ONLY, new_hyper_ratchet.clone(), security_level);
                    let hole_puncher = UdpHolePuncher::new(conn, RelativeNodeType::Initiator, generate_hole_punch_crypt_container(new_hyper_ratchet.clone(), SecurityLevel::LOW, C2S_ENCRYPTION_ONLY));
                    log::info!("Initiator created");
                    std::mem::drop(state_container);

                    match hole_puncher.await {
                        Ok(ret) => {
                            log::info!("Initiator finished NAT traversal ...");
                            send_success_as_initiator(ret, &new_hyper_ratchet, session, security_level, VirtualTargetType::HyperLANPeerToHyperLANServer(cnac.get_cid()))
                        }

                        Err(err) => {
                            log::warn!("Hole punch attempt failed. Will exit session: {:?}", err);
                            // Note: this currently implies that if NAT traversal fails, the session does not open
                            PrimaryProcessorResult::EndSession("UDP NAT traversal failed")
                        }
                    }
                } else {
                    log::error!("Invalid SYN_ACK");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Expected stage SYN_ACK, but local state was not");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_preconnect::STAGE0 => {
            log::info!("RECV STAGE 0 PRE_CONNECT PACKET");

            // At this point, the user's static-key identity has been verified. We can now check the online status to ensure no double-logins

            let udp_mode = session.udp_mode.get();
            let ref cnac = session.cnac.get()?;
            let hyper_ratchet = cnac.get_hyper_ratchet(Some(header.drill_version.get()))?;
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                if let Some(_) = validation::pre_connect::validate_stage0(&hyper_ratchet, packet) {

                    let timestamp = session.time_tracker.get_global_time_ns();
                    // since this is the server, we use whatever our primary listener is bound to defined in HdpServer::init
                    let local_bind_addr = session.local_bind_addr;

                    let peer_nat_type = session.adjacent_nat_type.clone()?;
                    let peer_accessible = peer_nat_type.predict_external_addr_from_local_bind_port(0).is_some();

                    if udp_mode == UdpMode::Disabled || !peer_accessible {
                        if !peer_accessible && udp_mode == UdpMode::Enabled {
                            log::warn!("UDP NAT Traversal is not possible. Will use default TCP connection")
                        }

                        // since this node is the server, send a BEGIN CONNECT signal to alice
                        // We have to modify the state to ensure that this node can receive a DO_CONNECT packet
                        state_container.pre_connect_state.success = true;
                        let packet = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        return PrimaryProcessorResult::ReplyToSender(packet);
                    } // .. otherwise, continue logic below to punch a hole through the firewall

                    let _local_node_type = session.local_node_type;
                    let peer_addr = session.remote_peer;
                    let _peer_internal_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;
                    let to_primary_stream = session.to_primary_stream.clone()?;

                    let conn = HolePunchCompatStream::new(to_primary_stream, &mut *state_container, peer_addr, local_bind_addr, C2S_ENCRYPTION_ONLY, hyper_ratchet.clone(), security_level);
                    let hole_puncher = UdpHolePuncher::new(conn, RelativeNodeType::Receiver, generate_hole_punch_crypt_container(hyper_ratchet.clone(), SecurityLevel::LOW, C2S_ENCRYPTION_ONLY));
                    log::info!("Receiver created");
                    std::mem::drop(state_container);

                    match hole_puncher.await {
                        Ok(ret) => {
                            let sess = session_orig;

                            let HolePunchedUdpSocket { socket, addr } = ret;

                            let mut state_container = inner_mut!(sess.state_container);
                            let tcp_loaded_alerter_rx = state_container.setup_tcp_alert_if_udp_c2s();

                            log::info!("UDP hole-punch SUCCESS! Sending a RECEIVER_FINISHED_HOLE_PUNCH");

                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                            state_container.pre_connect_state.on_packet_received(); // this is hacky. Just to help prevent a timeout
                            std::mem::drop(state_container);

                            // the UDP subsystem will automatically engage at this point
                            HdpSession::udp_socket_loader(sess.clone(), VirtualTargetType::HyperLANPeerToHyperLANServer(cnac.get_cid()), determine_udp_interface(session, socket, addr.natted), addr, sess.kernel_ticket.get(), Some(tcp_loaded_alerter_rx));
                            // the server will await for the client to send an initiation packeet
                            PrimaryProcessorResult::Void
                        }

                        Err(err) => {
                            log::info!("Hole punch attempt failed ({}). Will fallback to TCP only mode. Will await for adjacent node to continue exchange", err.to_string());
                            // We await the initiator to choose a method
                            let session = session_orig;
                            session.udp_mode.set(UdpMode::Disabled);
                            let mut state_container = inner_mut!(session.state_container);
                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                            PrimaryProcessorResult::Void
                        }
                    }
                } else {
                    log::error!("Unable to validate stage 0 packet");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Packet state 0, last stage not 0. Dropping");
                PrimaryProcessorResult::Void
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
            let mut state_container = inner_mut!(session.state_container);
            let ref cnac = session.cnac.get()?;
            let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;
                if let Some(hyper_ratchet) = validation::pre_connect::validate_final(cnac, packet) {
                    state_container.pre_connect_state.success = true;
                    if !success {
                        session.udp_mode.set(UdpMode::Disabled);
                    }

                    // if we are using tcp_only, skip the rest and go straight to sending the packet
                    if tcp_only {
                        log::warn!("Received signal to fall-back to TCP only mode");
                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        return PrimaryProcessorResult::ReplyToSender(begin_connect);
                    }

                    // if we aren't using tcp only, and, failed, end the session
                    if !tcp_only && !success {
                        let ticket = state_container.pre_connect_state.ticket.unwrap_or_else(|| session.kernel_ticket.get());
                        std::mem::drop(state_container);
                        session.needs_close_message.set(false);
                        session.send_to_kernel(HdpServerResult::ConnectFail(ticket, Some(cnac.get_cid()), "Preconnect stage failed".to_string()))?;
                        PrimaryProcessorResult::EndSession("Failure packet received")
                    } else {
                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        PrimaryProcessorResult::ReplyToSender(begin_connect)
                    }
                } else {
                    log::error!("Unable to validate success packet. Dropping");
                    PrimaryProcessorResult::Void
                }
        }

        // the client gets this. The client must now begin the connect process
        packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT => {
            log::info!("RECV STAGE BEGIN_CONNECT PRE CONNECT PACKET");
            let mut state_container = inner_mut!(session.state_container);
            let ref cnac = session.cnac.get()?;

            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SUCCESS {
                if let Some(hyper_ratchet) = validation::pre_connect::validate_begin_connect(cnac, packet) {
                    state_container.pre_connect_state.success = true;
                    std::mem::drop(state_container);
                    // now, begin stage 0 connect
                    begin_connect_process(&session, &hyper_ratchet, security_level)
                } else {
                    log::error!("Unable to validate success_ack packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Last stage is not SUCCESS, yet a BEGIN_CONNECT packet was received. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_preconnect::HALT => {
            let message = String::from_utf8(payload.to_vec()).unwrap_or("INVALID UTF-8".into());
            let ticket = session.kernel_ticket.get();
            session.send_to_kernel(HdpServerResult::ConnectFail(ticket, Some(header.session_cid.get()), message))?;
            session.needs_close_message.set(false);
            PrimaryProcessorResult::EndSession("Preconnect signalled to halt")
        }

        _ => {
            log::error!("Invalid auxiliary command");
            PrimaryProcessorResult::Void
        }
    }
}

fn begin_connect_process(session: &HdpSession, hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> PrimaryProcessorResult {
    // at this point, the session keys have already been re-established. We just need to begin the login stage
    let mut state_container = inner_mut!(session.state_container);
    let timestamp = session.time_tracker.get_global_time_ns();
    let proposed_credentials = state_container.connect_state.proposed_credentials.take()?;
    let fcm_keys = session.fcm_keys.clone();

    let stage0_connect_packet = crate::hdp::hdp_packet_crafter::do_connect::craft_stage0_packet(&hyper_ratchet, proposed_credentials, fcm_keys, timestamp, security_level);
    state_container.connect_state.last_stage = packet_flags::cmd::aux::do_connect::STAGE1;
    // we now store the pqc temporarily in the state container
    //session.post_quantum = Some(new_pqc);
    std::mem::drop(state_container);
    session.state.set(SessionState::ConnectionProcess);

    log::info!("Successfully sent stage0 connect packet outbound");

    // Keep the session open even though we transitioned from the pre-connect to connect stage
    PrimaryProcessorResult::ReplyToSender(stage0_connect_packet)
}

fn send_success_as_initiator(hole_punched_socket: HolePunchedUdpSocket, hyper_ratchet: &HyperRatchet, session: &HdpSession, security_level: SecurityLevel, v_target: VirtualTargetType) -> PrimaryProcessorResult {
    let HolePunchedUdpSocket { socket, addr } = hole_punched_socket;
    let mut state_container = inner_mut!(session.state_container);
    let tcp_loaded_alerter_rx = state_container.setup_tcp_alert_if_udp_c2s();
    log::info!("UDP Hole punch success! Sending a SUCCESS packet to the receiver");
    let timestamp = session.time_tracker.get_global_time_ns();

    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
    state_container.pre_connect_state.on_packet_received();
    let success_packet = hdp_packet_crafter::pre_connect::craft_stage_final(hyper_ratchet, true, false, timestamp,  security_level);
    std::mem::drop(state_container);

    HdpSession::udp_socket_loader(session.clone(), v_target, determine_udp_interface(session, socket, addr.natted), addr, session.kernel_ticket.get(), Some(tcp_loaded_alerter_rx));
    PrimaryProcessorResult::ReplyToSender(success_packet)
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

fn determine_udp_interface(session: &HdpSession, socket: UdpSocket, peer_addr: SocketAddr) -> UdpSplittableTypes {
    if let Some(quic_conn) = session.this_quic_conn.take() {
        log::info!("Will use QUIC UDP datagrams for UDP transmission");
        UdpSplittableTypes::QUIC(QuicUdpSocketConnector::new(quic_conn, session.local_bind_addr))
    } else {
        log::info!("Will use Raw UDP for UDP transmission");
        UdpSplittableTypes::Raw(RawUdpSocketConnector::new(socket, peer_addr))
    }
}