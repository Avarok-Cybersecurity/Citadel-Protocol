use tokio::net::UdpSocket;

use hyxe_nat::error::FirewallError;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::udp_traversal::NatTraversalMethod;

use crate::constants::{HOLE_PUNCH_SYNC_TIME_MULTIPLIER, MULTIPORT_END, MULTIPORT_START};
use crate::hdp::nat_handler::determine_initial_nat_method;

use super::includes::*;
use std::sync::atomic::Ordering;
use hyxe_nat::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hdp::hdp_packet::packet_flags::payload_identifiers;

/// Handles preconnect packets. Handles the NAT traversal
/// TODO: Note to future programmers. This source file is not the cleanest, and in my opinion the dirtiest file in the entire codebase.
/// This will NEED to be refactored. It's also buggy in some cases. For 99% of cases, it does the job though
pub fn process(session_orig: &HdpSession, packet: HdpPacket, peer_addr: SocketAddr) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session_orig);

    if !session.is_provisional() {
        log::error!("Pre-Connect packet received, but the system is not in a provisional state. Dropping");
        return PrimaryProcessorResult::Void;
    }

    let (header, payload) = packet.parse()?;
    let header = &header;
    let security_level = header.security_level.into();

    match header.cmd_aux {
        packet_flags::cmd::aux::do_preconnect::SYN => {
            log::info!("RECV STAGE SYN PRE_CONNECT PACKET");
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN {
                if let Some(cnac) = session.account_manager.get_client_by_cid(header.session_cid.get()) {
                    let tcp_only = header.context_info.get() == 1;
                    let kat = header.target_cid.get() as i64;
                    let adjacent_proto_version = header.group.get();

                    match validation::pre_connect::validate_syn(&cnac, packet){
                        Some((static_aux_ratchet, transfer)) => {
                            // since the SYN's been validated, the CNACs toolset has been updated
                            let new_session_sec_lvl = transfer.security_level;
                            // TODO: prevent logins if versions out of sync. For now, don't
                            if proto_version_out_of_sync(adjacent_proto_version) {
                                log::warn!("\nLocal protocol version: {} | Adjacent protocol version: {} | Versions out of sync; program may not function\n", crate::constants::BUILD_VERSION, adjacent_proto_version);
                            }

                            log::info!("Synchronizing toolsets. TCP only? {}. Session security level: {:?}", tcp_only, new_session_sec_lvl);
                            // TODO: Rate limiting to prevent SYN flooding
                            let timestamp = session.time_tracker.get_global_time_ns();

                            // here, we also send the peer's external address to itself
                            // Also, we use the security level that was created on init b/c the other side still uses the static aux ratchet
                            let syn_ack = hdp_packet_crafter::pre_connect::craft_syn_ack(&static_aux_ratchet, transfer,  timestamp, peer_addr, security_level);

                            state_container.pre_connect_state.on_packet_received();

                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                            state_container.keep_alive_timeout_ns = kat;

                            std::mem::drop(state_container);

                            session.security_level = new_session_sec_lvl;
                            session.tcp_only = tcp_only;
                            session.cnac = Some(cnac);

                            PrimaryProcessorResult::ReplyToSender(syn_ack)
                        }

                        None => {
                            log::error!("Invalid SYN packet received");
                            PrimaryProcessorResult::Void
                        }
                    }
                } else {
                    let bad_cid = header.session_cid.get();
                    let error = format!("CID {} is not registered to this node", bad_cid);
                    let packet = hdp_packet_crafter::pre_connect::craft_halt(header, &error);
                    PrimaryProcessorResult::ReplyToSender(packet)
                }
            } else {
                log::error!("Expected stage SYN, but local state was not");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_preconnect::SYN_ACK => {
            log::info!("RECV STAGE SYN_ACK PRE_CONNECT PACKET");
            let tcp_only = session.tcp_only;
            // we now shadow the security_level above, and ensure all further packets use the desired default
            let security_level = session.security_level;
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                // cnac should already be loaded locally
                let cnac = session.cnac.as_ref()?;
                let alice_constructor = state_container.pre_connect_state.constructor.take()?;

                if let Some((new_hyper_ratchet, external_ip)) = validation::pre_connect::validate_syn_ack(cnac, alice_constructor, packet) {
                    // The toolset, at this point, has already been updated. The CNAC can be used to
                    //let ref drill = cnac.get_drill_blocking(None)?;
                    session.external_addr.store(Some(external_ip), Ordering::SeqCst);
                    let local_node_type = session.local_node_type;
                    let timestamp = session.time_tracker.get_global_time_ns();
                    let ticket = session.kernel_ticket;
                    let local_bind_addr = session.local_bind_addr.ip();

                    if tcp_only {
                        let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, local_node_type, &Vec::with_capacity(0), timestamp, peer_addr, security_level);
                        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                        return PrimaryProcessorResult::ReplyToSender(stage0_preconnect_packet);
                    }

                    match LinearUDPHolePuncher::reserve_new_udp_sockets((MULTIPORT_END - MULTIPORT_START) as usize, local_bind_addr) {
                        Ok(reserved_sockets) => {
                            let ref reserved_local_wave_ports = reserved_sockets.iter().map(|sck| sck.local_addr().unwrap().port()).collect::<Vec<u16>>();

                            let stage0_preconnect_packet = hdp_packet_crafter::pre_connect::craft_stage0(&new_hyper_ratchet, local_node_type, reserved_local_wave_ports, timestamp, peer_addr, security_level);

                            // store these sockets for later use
                            state_container.pre_connect_state.reserved_sockets = Some(reserved_sockets);
                            state_container.pre_connect_state.ticket = Some(ticket);
                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE1;
                            state_container.pre_connect_state.on_packet_received();

                            PrimaryProcessorResult::ReplyToSender(stage0_preconnect_packet)
                        }

                        Err(err) => {
                            log::error!("Unable to reserve local sockets. Reason: {}", err.to_string());
                            PrimaryProcessorResult::EndSession("Unable to reserve local sockets")
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
            let tcp_only = session.tcp_only;
            let timestamp_header = header.timestamp.get();
            let cnac = session.cnac.as_ref()?;
            let hyper_ratchet = cnac.get_hyper_ratchet(Some(header.drill_version.get()))?;
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SYN_ACK {
                if let Some((adjacent_node_type, adjacent_unnated_ports, external_ip)) = validation::pre_connect::validate_stage0(&hyper_ratchet, packet) {
                    // the server now has its external IP
                    session.external_addr.store(Some(external_ip), Ordering::SeqCst);
                    let timestamp = session.time_tracker.get_global_time_ns();
                    let local_bind_ip = session.local_bind_addr.ip();
                    let remote_ip = session.remote_peer.ip();
                    let wave_port_count = adjacent_unnated_ports.len();

                    if tcp_only {
                        // since this node is the server, send a BEGIN CONNECT signal to alice
                        // We have to modify the state to ensure that this node can receive a DO_CONNECT packet
                        state_container.pre_connect_state.success = true;
                        let packet = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        return PrimaryProcessorResult::ReplyToSender(packet);
                    } // .. otherwise, continue logic below to punch a hole through the firewall

                    // since self is the receiver, the ports on these endpoints dont matter since only the IP is checked. Play the game anyways
                    let endpoints = adjacent_unnated_ports.iter().map(|port| SocketAddr::new(remote_ip, *port)).collect::<Vec<SocketAddr>>();

                    let local_node_type = session.local_node_type;
                    let initial_traversal_method = determine_initial_nat_method(local_node_type, adjacent_node_type);
                    state_container.pre_connect_state.adjacent_node_type = Some(adjacent_node_type);
                    state_container.pre_connect_state.adjacent_unnated_ports = Some(adjacent_unnated_ports);
                    state_container.pre_connect_state.current_nat_traversal_method = Some(initial_traversal_method);

                    let (sync_time_instant, sync_time_ns) = calculate_sync_time(timestamp, timestamp_header);

                    // reserve ports
                    match LinearUDPHolePuncher::reserve_new_udp_sockets(wave_port_count, local_bind_ip) {
                        Ok(reserved_sockets) => {
                            let ref local_wave_ports = reserved_sockets.iter().map(|sck| sck.local_addr().unwrap().port()).collect::<Vec<u16>>();
                            let stage1_packet = hdp_packet_crafter::pre_connect::craft_stage1(&hyper_ratchet, local_node_type, local_wave_ports, initial_traversal_method, timestamp, sync_time_ns, security_level);
                            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE1;
                            state_container.pre_connect_state.on_packet_received();

                            if initial_traversal_method == NatTraversalMethod::UPnP {
                                // If UPnP is the method, then just send the stage 1 packet w/o the spawned task, Have the client send the ports in the SUCCESS packet back
                                state_container.pre_connect_state.reserved_sockets = Some(reserved_sockets);
                            } else {
                                std::mem::drop(state_container);
                                std::mem::drop(session);
                                // this runs the task. The receiver will wait til the sync_time, and will then automatically begin the hole-punching process
                                handle_nat_traversal_as_receiver(session_orig.clone(), hyper_ratchet, initial_traversal_method, sync_time_instant, endpoints, reserved_sockets, security_level);
                            }

                            PrimaryProcessorResult::ReplyToSender(stage1_packet)
                        }

                        Err(err) => {
                            // let this session timeout on the clientside
                            log::error!("Unable to reserve sockets: {}", err.to_string());
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

        // Alice, the initiator, gets this packet
        packet_flags::cmd::aux::do_preconnect::STAGE1 => {
            log::info!("RECV STAGE 1 PRE_CONNECT PACKET");
            let timestamp = session.time_tracker.get_global_time_ns();
            let endpoint_ip = session.remote_peer.ip();
            let hyper_ratchet = session.cnac.as_ref()?.get_hyper_ratchet(Some(header.drill_version.get()))?;
            let mut state_container = inner_mut!(session.state_container);
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::STAGE1 {

                if let Some((adjacent_node_type, proposed_traversal_method, sync_time, base_wave_ports)) = validation::pre_connect::validate_stage1(&hyper_ratchet, packet) {
                    // it is expected that these base_wave_ports are reachable from this node
                    let endpoints = base_wave_ports.iter().map(|adjacent_port| SocketAddr::new(endpoint_ip, *adjacent_port)).collect::<Vec<SocketAddr>>();
                    state_container.pre_connect_state.adjacent_node_type = Some(adjacent_node_type);
                    state_container.pre_connect_state.current_nat_traversal_method = Some(proposed_traversal_method);
                    state_container.pre_connect_state.adjacent_unnated_ports = Some(base_wave_ports);
                    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT;
                    state_container.pre_connect_state.on_packet_received();

                    // We must generate the endpoints
                    let time_til_sync = i64::abs(sync_time - timestamp) as u64;

                    let sync_time = if proposed_traversal_method == NatTraversalMethod::UPnP {
                        None
                    } else {
                        let sync_time = Instant::now() + Duration::from_nanos(time_til_sync);
                        Some(sync_time)
                    };

                    let reserved_sockets = state_container.pre_connect_state.reserved_sockets.take()?;
                    log::info!("NAT Traversal type: {}", proposed_traversal_method);
                    log::info!("Time til sync (ms): {}", time_til_sync / 1_000_000);
                    // As the sync_time, the hole punching process will start
                    std::mem::drop(state_container);
                    std::mem::drop(session);
                    handle_nat_traversal_as_initiator(session_orig.clone(), hyper_ratchet, proposed_traversal_method, sync_time, endpoints, reserved_sockets, security_level);
                    PrimaryProcessorResult::Void
                } else {
                    log::error!("Unable to validate stage 1 preconnect packet");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Packet state 1, last stage not 1. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        // alice gets this message as a response from the server, who just finished attempting the hole-punch process
        packet_flags::cmd::aux::do_preconnect::RECEIVER_FINISHED_HOLE_PUNCH => {
            log::info!("RECV STAGE RECEIVER_FINISHED_HOLE_PUNCH PRE_CONNECT PACKET");

            let mut state_container = inner_mut!(session.state_container);
            let hyper_ratchet = session.cnac.as_ref()?.get_hyper_ratchet(Some(header.drill_version.get()))?;
            let this_node_last_state = state_container.pre_connect_state.last_stage;
            // the initiator will set this as SUCCESS
            if this_node_last_state == packet_flags::cmd::aux::do_preconnect::SUCCESS || this_node_last_state == packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT {
                let receiver_success = header.algorithm == 1;
                if let Some(_) = validation::pre_connect::validate_server_finished_hole_punch(&hyper_ratchet, packet) {
                    // Localhost testing problem: The hole puncher may not have finished by the time this gets called, and thus the state would not
                    // have updated (yet).
                    log::info!("RECV SUCCESS? {}", receiver_success);
                    if receiver_success && this_node_last_state == packet_flags::cmd::aux::do_preconnect::SUCCESS {
                        let method = state_container.pre_connect_state.current_nat_traversal_method?;
                        let set = state_container.pre_connect_state.hole_punched.take()?;
                        // If the method used was UPnP, we must tell the adjacent node which ports it must send to in order to reach the local node
                        std::mem::drop(state_container);
                        send_success_as_initiator(set, method, &hyper_ratchet, &mut wrap_inner_mut!(session), security_level)
                    } else {
                        log::warn!("Initiator/Receiver did not succeed. Must send a TRY_NEXT");
                        let timestamp = session.time_tracker.get_global_time_ns();
                        if let Some(hole_puncher) = state_container.pre_connect_state.hole_puncher.take() {
                            if let Some(next_method) = hole_puncher.get_next_method() {
                                // We still have unused methods. Send a TRY_NEXT packets
                                log::info!("[Firewall] Will attempt {:?}", &next_method);
                                state_container.pre_connect_state.nat_traversal_attempts += 1;
                                state_container.pre_connect_state.current_nat_traversal_method = Some(next_method);
                                state_container.pre_connect_state.hole_puncher = Some(hole_puncher);
                                // Set stage to TRY_NEXT to allow the reception of a TRY_NEXT_ACK
                                state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT;
                                // since this is the initiator, we send a TRY_AGAIN packet
                                // set to failure to allow the next

                                let try_next_packet = hdp_packet_crafter::pre_connect::craft_stage_try_next(&hyper_ratchet, next_method, timestamp, security_level);
                                return PrimaryProcessorResult::ReplyToSender(try_next_packet);
                            }
                        }

                        // this means we've used up all the methods, or if we failed. For now, instantly fall-back to TCP
                        // TODO: Comprehensive NAT traversal
                        log::info!("[Firewall] [TCP-ONLY] ALL methods used. Unable to penetrate firewall. Falling-back to TCP only mode");
                        // Use TCP only mode
                        let success_packet = hdp_packet_crafter::pre_connect::craft_stage_final(&hyper_ratchet, false, true, timestamp, None, security_level);
                        // this will allow future DO_CONNECTS to get processed
                        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                        state_container.pre_connect_state.success = true;
                        std::mem::drop(state_container);
                        session.tcp_only = true;
                        PrimaryProcessorResult::ReplyToSender(success_packet)
                    }
                } else {
                    log::error!("Invalid packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Received a RECEIVER_FINISHED_HOLE_PUNCH packet, but last stage is not SUCCESS. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        // The receiver receives this packet
        packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT => {
            log::info!("RECV STAGE TRY_NEXT PRE CONNECT PACKET");
            let header_timestamp = header.timestamp.get();
            let timestamp = session.time_tracker.get_global_time_ns();
            let remote_ip = session.remote_peer.ip();
            let mut state_container = inner_mut!(session.state_container);
            let cnac = session.cnac.as_ref()?;
            let this_node_last_stage = state_container.pre_connect_state.last_stage;
            // if the hole punching fails, the server sets it stage to failure and await for the client to return this TRY_NEXT packet
            if this_node_last_stage == packet_flags::cmd::aux::do_preconnect::SUCCESS || this_node_last_stage == packet_flags::cmd::aux::do_preconnect::FAILURE {
                if let Some((hyper_ratchet, next_traversal_method)) = validation::pre_connect::validate_try_next(cnac, packet) {
                    state_container.pre_connect_state.current_nat_traversal_method = Some(next_traversal_method);
                    // we must now start the receiver fn, using the data
                    let preserved_sockets = state_container.pre_connect_state.reserved_sockets.take()?;
                    let (sync_time_instant, sync_time_ns) = calculate_sync_time(timestamp, header_timestamp);
                    let adjacent_unnated_ports = state_container.pre_connect_state.adjacent_unnated_ports.clone()?;
                    let endpoints = adjacent_unnated_ports.iter().map(|port| SocketAddr::new(remote_ip, *port)).collect::<Vec<SocketAddr>>();

                    // send a TRY_NEXT_ACK now with the proper sync_time
                    let try_next_ack = hdp_packet_crafter::pre_connect::craft_stage_try_next_ack(&hyper_ratchet, timestamp, sync_time_ns, security_level);
                    std::mem::drop(state_container);
                    std::mem::drop(session);

                    handle_nat_traversal_as_receiver(session_orig.clone(), hyper_ratchet, next_traversal_method, sync_time_instant, endpoints, preserved_sockets, security_level);
                    PrimaryProcessorResult::ReplyToSender(try_next_ack)
                } else {
                    log::error!("Unable to validate TRY_NEXT packet");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Received a TRY_NEXT packet, but the last stage was not beyond stage 1. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        // the initiator gets this packet. The packet will contain the sync time, similar to the stage 1 packet it received earlier
        packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT_ACK => {
            log::info!("RECV STAGE TRY_NEXT_ACK PRE CONNECT PACKET");
            let timestamp = session.time_tracker.get_global_time_ns();
            let endpoint_ip = session.remote_peer.ip();
            let mut state_container = inner_mut!(session.state_container);
            let cnac = session.cnac.as_ref()?;

            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT {
                if let Some((hyper_ratchet, sync_time)) = validation::pre_connect::validate_try_next_ack(cnac, packet) {
                    // it is expected that these base_wave_ports are reachable from this node (when coupled with the remote IP)
                    let base_wave_ports = state_container.pre_connect_state.adjacent_unnated_ports.clone()?;
                    //let adjacent_node_type = state_container.pre_connect_state.adjacent_node_type.clone()?;
                    let endpoints = base_wave_ports.iter().map(|adjacent_port| SocketAddr::new(endpoint_ip, *adjacent_port)).collect::<Vec<SocketAddr>>();

                    let proposed_traversal_method = state_container.pre_connect_state.current_nat_traversal_method.clone()?;

                    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT_ACK;
                    state_container.pre_connect_state.on_packet_received();

                    // We must generate the endpoints
                    let time_til_sync = i64::abs(sync_time - timestamp) as u64;

                    let sync_time = if proposed_traversal_method == NatTraversalMethod::UPnP {
                        None
                    } else {
                        let sync_time = Instant::now() + Duration::from_nanos(time_til_sync);
                        Some(sync_time)
                    };

                    let reserved_sockets = state_container.pre_connect_state.reserved_sockets.take()?;

                    log::info!("Time til sync (ms): {}", time_til_sync / 1_000_000);
                    // As the sync_time, the hole punching process will start
                    std::mem::drop(state_container);
                    std::mem::drop(session);
                    handle_nat_traversal_as_initiator(session_orig.clone(), hyper_ratchet, proposed_traversal_method, sync_time, endpoints, reserved_sockets, security_level);
                    PrimaryProcessorResult::Void
                } else {
                    log::error!("Unable to validate stage TRY_NEXT_ACK");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Not in stage TRY_NEXT. Aborting");
                PrimaryProcessorResult::Void
            }
        }

        // Alice (initiator) sends this to Bob (receiver)
        packet_flags::cmd::aux::do_preconnect::SUCCESS => {
            log::info!("RECV STAGE SUCCESS PRE CONNECT PACKET");
            let timestamp = session.time_tracker.get_global_time_ns();
            let remote_ip = session.remote_peer.ip();
            let mut state_container = inner_mut!(session.state_container);
            let cnac = session.cnac.as_ref()?;
            let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;
            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SUCCESS {
                if let Some((hyper_ratchet, upnp_ports_opt)) = validation::pre_connect::validate_final(cnac, packet, tcp_only) {
                    // if we are using tcp_only, skip the rest and go straight to sending the packet
                    if tcp_only {
                        log::warn!("Received signal to fall-back to TCP only mode");
                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        return PrimaryProcessorResult::ReplyToSender(begin_connect);
                    }

                    if let Some(upnp_ports) = upnp_ports_opt {
                        if state_container.pre_connect_state.current_nat_traversal_method.unwrap() == NatTraversalMethod::UPnP {
                            // since this is the receiver, the hole-punched addrs will have initial.ip() == remote_ip == natted.ip()
                            // the initial ports will be the stored unnated ports. The natted ports will be the upnp ports

                            // Also: the sockets are stored for us to take here
                            // grab the stored udp sockets
                            let reserved_sockets = state_container.pre_connect_state.reserved_sockets.take()?;
                            let unnatted_ports = state_container.pre_connect_state.adjacent_unnated_ports.take()?;

                            let hole_punched_addrs = unnatted_ports.into_iter().zip(upnp_ports.into_iter()).map(|(unnatted_port, upnp_port)| HolePunchedSocketAddr::new(SocketAddr::new(remote_ip, unnatted_port), SocketAddr::new(remote_ip, upnp_port))).collect::<Vec<HolePunchedSocketAddr>>();
                            let set = reserved_sockets.into_iter().zip(hole_punched_addrs.into_iter()).collect::<Vec<(UdpSocket, HolePunchedSocketAddr)>>();
                            // we have the reserved sockets and the hole punched addrs. Now, start this server-side socket loader
                            // We must set this value to 'true' in order for this node to receive a stage 0 DO_CONNECT packet after Bob sends back the SUCCESS_ACK
                            state_container.pre_connect_state.success = true;
                            state_container.pre_connect_state.on_packet_received();

                            std::mem::drop(state_container);

                            match session.wave_socket_loader.take().unwrap().send(set) {
                                Ok(_) => {
                                    let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                                    PrimaryProcessorResult::ReplyToSender(begin_connect)
                                }

                                Err(_) => {
                                    log::error!("Server unable to send set through wave socket loader");
                                    PrimaryProcessorResult::Void
                                }
                            }
                        } else {
                            log::error!("UPnP ports provided, but the NAT traversal method was not UPnP. Check program logic");
                            PrimaryProcessorResult::Void
                        }
                    } else {
                        // non-upnp traversal method (e.g, method3). Set state to success and send SUCCESS ACK
                        state_container.pre_connect_state.success = true;
                        state_container.pre_connect_state.on_packet_received();

                        let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                        PrimaryProcessorResult::ReplyToSender(begin_connect)
                    }
                } else {
                    log::error!("Unable to validate success packet. Dropping");
                    PrimaryProcessorResult::Void
                }
            } else {
                log::error!("Last stage is not SUCCESS, yet a SUCCESS packet was received. Dropping");
                PrimaryProcessorResult::Void
            }
        }

        packet_flags::cmd::aux::do_preconnect::FAILURE => {
            log::info!("RECV STAGE FAILURE PRE CONNECT PACKET");
            let cnac = session.cnac.as_ref()?;
            let cid = cnac.get_id();
            let timestamp = session.time_tracker.get_global_time_ns();
            let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;
            let mut state_container = inner_mut!(session.state_container);
            if let Some((hyper_ratchet, _upnp_ports)) = validation::pre_connect::validate_final(cnac, packet, tcp_only) {
                if tcp_only {
                    log::info!("Hole-punching failed, but falling-back to TCP-ONLY mode instead (network performance may decrease in throughput)");
                    state_container.pre_connect_state.success = true;
                    std::mem::drop(state_container);
                    session.tcp_only = true;
                    // To trigger the client's initiation of the DO_CONNECT process, send a BEGIN_CONNECT packet
                    let begin_connect = hdp_packet_crafter::pre_connect::craft_begin_connect(&hyper_ratchet, timestamp, security_level);
                    PrimaryProcessorResult::ReplyToSender(begin_connect)
                } else {
                    let ticket = state_container.pre_connect_state.ticket.unwrap_or(session.kernel_ticket);
                    std::mem::drop(state_container);
                    session.needs_close_message.store(false, Ordering::SeqCst);
                    session.send_to_kernel(HdpServerResult::ConnectFail(ticket, Some(cid), "Preconnect stage failed".to_string()))?;
                    PrimaryProcessorResult::EndSession("Failure packet received")
                }
            } else {
                log::error!("Unable to validate stage final preconnect packet");
                PrimaryProcessorResult::Void
            }
        }

        // the client gets this. The client must now begin the connect process
        packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT => {
            log::info!("RECV STAGE BEGIN_CONNECT PRE CONNECT PACKET");
            let mut state_container = inner_mut!(session.state_container);
            let cnac = session.cnac.as_ref()?;

            if state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::SUCCESS || state_container.pre_connect_state.last_stage == packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT {
                if let Some(hyper_ratchet) = validation::pre_connect::validate_begin_connect(cnac, packet) {
                    state_container.pre_connect_state.success = true;
                    std::mem::drop(state_container);
                    // now, begin stage 0 connect
                    begin_connect_process(wrap_inner_mut!(session), &hyper_ratchet, security_level)
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
            let ticket = session.kernel_ticket;
            session.send_to_kernel(HdpServerResult::ConnectFail(ticket, Some(header.session_cid.get()), message))?;
            session.needs_close_message.store(false, Ordering::Relaxed);
            PrimaryProcessorResult::EndSession("Preconnect signalled to halt")
        }

        _ => {
            log::error!("Invalid auxiliary command");
            PrimaryProcessorResult::Void
        }
    }
}

/// This must spawn an asynchronous task in b/c of the inherit blocking mechanisms
#[allow(unused_results)]
fn handle_nat_traversal_as_receiver(session: HdpSession, hyper_ratchet: HyperRatchet, method: NatTraversalMethod, sync_time: Instant, endpoints: Vec<SocketAddr>, sockets: Vec<UdpSocket>, security_level: SecurityLevel) {
    spawn!(handle_nat_traversal_as_receiver_inner(session, hyper_ratchet, method, sync_time, endpoints, sockets, security_level));
}

#[allow(unused_results)]
async fn handle_nat_traversal_as_receiver_inner(session_orig: HdpSession, hyper_ratchet: HyperRatchet, method: NatTraversalMethod, sync_time: Instant, endpoints: Vec<SocketAddr>, mut sockets: Vec<UdpSocket>, security_level: SecurityLevel) {
    let mut hole_puncher = {
        tokio::time::sleep_until(sync_time).await;
        log::info!("Synchronize time reached. Executing hole punch subroutine ...");
        let session = inner!(session_orig);
        let crypt_container = generate_hole_punch_crypt_container(hyper_ratchet.clone(), security_level);
        let local_node_type = session.local_node_type;
        let hole_puncher = LinearUDPHolePuncher::new_receiver(local_node_type, Some(crypt_container));
        //std::mem::drop(session);
        hole_puncher
    };

    match hole_puncher.try_method(&mut sockets, &endpoints, method).await {
        Ok(set) => {
            let mut sess = inner_mut!(session_orig);
            let timestamp = sess.time_tracker.get_global_time_ns();

            let set = sockets.into_iter().zip(set.into_iter()).collect::<Vec<(UdpSocket, HolePunchedSocketAddr)>>();
            match sess.wave_socket_loader.take().unwrap().send(set) {
                Ok(_) => {
                    // the UDP subsystem will automatically engage at this point
                    log::info!("UDP hole-punch SUCCESS! Sending a RECEIVER_FINISHED_HOLE_PUNCH");

                    let mut state_container = inner_mut!(sess.state_container);
                    state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                    state_container.pre_connect_state.on_packet_received(); // this is hacky. Just to help prevent a timeout
                    let finished_hole_punch = hdp_packet_crafter::pre_connect::craft_server_finished_hole_punch(&hyper_ratchet,true, timestamp, security_level);
                    std::mem::drop(state_container);
                    if sess.send_to_primary_stream(None, finished_hole_punch).is_err() {
                        log::error!("Primary stream disconnected");
                        sess.shutdown();
                    }
                }

                Err(_err) => {
                    // This is a weird error. Make sure the program can't get to this point
                    log::error!("Oneshot send failure");
                    let mut state_container = inner_mut!(sess.state_container);
                    let ticket = state_container.pre_connect_state.ticket;
                    state_container.pre_connect_state = Default::default(); // reset
                    let failure_packet = hdp_packet_crafter::pre_connect::craft_stage_final(&hyper_ratchet, false, false, timestamp, None, security_level);

                    std::mem::drop(state_container);
                    if sess.send_to_primary_stream(ticket, failure_packet).is_err() {
                        log::error!("Primary stream disconnected");
                    }
                    sess.shutdown();
                    return;
                }
            }
        }

        Err(FirewallError::NotApplicable) => {
            // If the next method was UPnP, then the receiver won't do anything as the client's job is to run this.
            // As such, this node should just await for the client's UPnP. We should set the stage to SUCCESS to allow
            // a success packet to come inbound (or, a failure. in which case the SUCCESS set below is not necessary)
            let session = inner!(session_orig);
            let mut state_container = inner_mut!(session.state_container);
            // store the sockets for later retrieval
            state_container.pre_connect_state.reserved_sockets = Some(sockets);
            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
            // Unlike above wherein the server sends a SERVER_FINISHED_HOLE_PUNCH, we wait for the client to send a success
        }

        Err(err) => {
            log::info!("Hole punch attempt failed ({}). Will fallback to TCP only mode. Will await for adjacent node to continue exchange", err.to_string());
            // We await the initiator to choose a method
            let mut session = inner_mut!(session_orig);
            session.tcp_only = true;
            let mut state_container = inner_mut!(session.state_container);
            // store the hole puncher so that it may be snatched once this node receives the TRY_AGAIN packet
            state_container.pre_connect_state.hole_puncher = Some(hole_puncher);
            state_container.pre_connect_state.reserved_sockets = Some(sockets);
            state_container.pre_connect_state.nat_traversal_attempts += 1;
            // set to failure to allow this node to process a TRY_NEXT packet
            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::FAILURE;
        }
    }
}

/// This must spawn an asynchronous task in b/c of the inherit blocking mechanisms
///
/// `sync_time`: If this is None, then the program won't delay and will work immediately
#[allow(unused_results)]
fn handle_nat_traversal_as_initiator(session: HdpSession, hyper_ratchet: HyperRatchet, method: NatTraversalMethod, sync_time: Option<Instant>, endpoints: Vec<SocketAddr>, sockets: Vec<UdpSocket>, security_level: SecurityLevel) {
    spawn!(handle_nat_traversal_as_initiator_inner(session, hyper_ratchet, method, sync_time, endpoints, sockets, security_level));
}

#[allow(unused_results)]
async fn handle_nat_traversal_as_initiator_inner(session_orig: HdpSession, hyper_ratchet: HyperRatchet, method: NatTraversalMethod, sync_time: Option<Instant>, endpoints: Vec<SocketAddr>, mut sockets: Vec<UdpSocket>, security_level: SecurityLevel) {
    let mut hole_puncher = {
        if let Some(sync_time) = sync_time {
            tokio::time::sleep_until(sync_time).await;
        }

        log::info!("Synchronize time reached. Executing hole punch subroutine ...");
        let session = inner!(session_orig);

        let crypt_container = generate_hole_punch_crypt_container(hyper_ratchet.clone(), security_level);
        let local_node_type = session.local_node_type;
        let hole_puncher = LinearUDPHolePuncher::new_initiator(local_node_type, Some(crypt_container));
        //std::mem::drop(session);
        hole_puncher
    };

    match hole_puncher.try_method(&mut sockets, &endpoints, method).await {
        Ok(set) => {
            let mut sess = inner_mut!(session_orig);
            let set = sockets.into_iter().zip(set.into_iter()).collect::<Vec<(UdpSocket, HolePunchedSocketAddr)>>();
            // if we aren't using UPnP, we will need to wait for the receiver to send its finish packet before continuing
            if method != NatTraversalMethod::UPnP {
                // Now, save the set
                let mut state_container = inner_mut!(sess.state_container);
                // set the last stage to SUCCESS to allow the reception of a SERVER_FINISHED_HOLE_PUNCH
                state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
                state_container.pre_connect_state.hole_punched = Some(set);
            } else {
                // if, however, we did use UPnP, then we are ready to send a SUCCESS packet
                match send_success_as_initiator(set, method, &hyper_ratchet, &mut wrap_inner_mut!(sess), security_level) {
                    PrimaryProcessorResult::ReplyToSender(packet) => {
                        if sess.send_to_primary_stream(None, packet).is_err() {
                            log::error!("Primary stream disconnected");
                            sess.shutdown();
                        }
                    }
                    PrimaryProcessorResult::EndSession(reason) => {
                        log::error!("{}", reason);
                        sess.shutdown();
                    }

                    _ => log::error!("Please don't let this happen")
                }
            }
        }

        Err(err) => {
            log::info!("Hole punch attempt failed. Must try again. Will await for the server to finish though ({})", err.to_string());
            let mut session = inner_mut!(session_orig);
            session.tcp_only = true;
            let mut state_container = inner_mut!(session.state_container);
            // set the last stage to STAGE_TRY_NEXT to allow the reception of the SERVER_FINISHED_HOLE_PUNCH packet
            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT;
            // Also, save the hole-puncher and sockets for re-use
            state_container.pre_connect_state.hole_puncher = Some(hole_puncher);
            state_container.pre_connect_state.reserved_sockets = Some(sockets);
        }
    }
}

fn begin_connect_process<K: ExpectedInnerTargetMut<HdpSessionInner>>(mut session: InnerParameterMut<K, HdpSessionInner>,  hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> PrimaryProcessorResult {
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
    session.state = SessionState::ConnectionProcess;

    log::info!("Successfully sent stage0 connect packet outbound");

    // Keep the session open even though we transitioned from the pre-connect to connect stage
    PrimaryProcessorResult::ReplyToSender(stage0_connect_packet)
}

fn send_success_as_initiator<K: ExpectedInnerTargetMut<HdpSessionInner>>(set: Vec<(UdpSocket, HolePunchedSocketAddr)>, method: NatTraversalMethod, hyper_ratchet: &HyperRatchet, session: &mut InnerParameterMut<K, HdpSessionInner>, security_level: SecurityLevel) -> PrimaryProcessorResult {
    let inscribe_ports = if method == NatTraversalMethod::UPnP {
        // collect the natted ports, since those are the reserved ports. The other end will then take the remote_ip (this node) and
        // couple it with these ports to know where to send packets to
        Some(set.iter().map(|hole_punched_addr| hole_punched_addr.1.natted.port()).collect::<Vec<u16>>())
    } else {
        None
    };

    // the below will panic if the socket loader is not inside the option
    match session.wave_socket_loader.take().unwrap().send(set) {
        Ok(_) => {
            log::info!("UDP Hole punch success! Sending a SUCCESS packet to the receiver");
            let timestamp = session.time_tracker.get_global_time_ns();
            let mut state_container = inner_mut!(session.state_container);
            state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS;
            state_container.pre_connect_state.on_packet_received();
            let success_packet = hdp_packet_crafter::pre_connect::craft_stage_final(hyper_ratchet, true, false, timestamp, inscribe_ports, security_level);
            PrimaryProcessorResult::ReplyToSender(success_packet)
        }

        Err(_) => {
            // This is a weird error. Make sure the program can't get to this point
            log::error!("Oneshot send failure");
            PrimaryProcessorResult::EndSession("session end")
        }
    }
}

fn generate_hole_punch_crypt_container(hyper_ratchet: HyperRatchet, security_level: SecurityLevel) -> EncryptedConfigContainer {
    let hyper_ratchet_cloned = hyper_ratchet.clone();
    EncryptedConfigContainer::new(move |local_port| {
        hdp_packet_crafter::hole_punch::generate_packet(&hyper_ratchet, local_port, security_level)
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