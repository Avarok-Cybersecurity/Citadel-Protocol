use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer, BobToAliceTransferType, HyperRatchetConstructor};
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::toolset::Toolset;
use hyxe_fs::prelude::SyncIO;

use crate::hdp::hdp_packet_processor::includes::*;
use crate::hdp::hdp_packet_processor::peer::group_broadcast;
use crate::hdp::hdp_packet_processor::preconnect_packet::{calculate_sync_time, generate_hole_punch_crypt_container};
use crate::hdp::hdp_packet_processor::primary_group_packet::{get_proper_hyper_ratchet, get_resp_target_cid};
use crate::hdp::hdp_server::Ticket;
use crate::hdp::peer::p2p_conn_handler::attempt_simultaneous_hole_punch;
use crate::hdp::peer::peer_crypt::{KeyExchangeProcess, PeerNatInfo};
use crate::hdp::peer::peer_layer::{HypernodeConnectionType, PeerConnectionType, PeerResponse, PeerSignal, UdpMode};
use crate::hdp::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use hyxe_user::external_services::fcm::kem::FcmPostRegister;
use bytes::BytesMut;
use crate::hdp::outbound_sender::OutboundPrimaryStreamSender;
use crate::hdp::hdp_session_manager::HdpSessionManager;
use std::sync::atomic::Ordering;
use hyxe_crypt::prelude::ConstructorOpts;
use crate::hdp::peer::hole_punch_compat_sink_stream::HolePunchCompatStream;
use hyxe_nat::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use hyxe_nat::udp_traversal::linear::RelativeNodeType;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use crate::hdp::misc::udp_internal_interface::UdpSplittableTypes;

#[allow(unused_results)]
/// Insofar, there is no use of endpoint-to-endpoint encryption for PEER_CMD packets because they are mediated between the
/// HyperLAN client and the HyperLAN Server
///
/// *** IMPORTANT RULE *** : NEVER get a mutable reference to an HdpSession under this function! IF you do, it has the potential to cause deadlocks under tight concurrent situations
/// b/c sessions sometimes need to access other sessions
pub async fn process(session_orig: &HdpSession, aux_cmd: u8, packet: HdpPacket, header_drill_version: u32, endpoint_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    // ALL PEER_CMD packets require that the current session contain a CNAC (not anymore since switching to async)
    let session = session_orig;
    // Some PEER_CMD packets get encrypted using the endpoint crypto
    let ref cnac = session.cnac.get()?;

    log::info!("RECV PEER CMD packet (proxy: {})", endpoint_cid_info.is_some());
    let mut state_container = inner_mut!(session.state_container);
    let sess_hyper_ratchet = return_if_none!(get_proper_hyper_ratchet(header_drill_version, cnac, &state_container, endpoint_cid_info), "Unable to obtain peer HR (P_CMD_PKT)");

    let (header, payload, peer_addr, _) = packet.decompose();
    let (header, payload) = validation::aead::validate_custom(&sess_hyper_ratchet, &header, payload)?;
    let security_level = header.security_level.into();
    log::info!("PEER CMD packet authenticated");

    match aux_cmd {
        packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST => {
            std::mem::drop(state_container);
            group_broadcast::process(session_orig, header, &payload[..], &sess_hyper_ratchet).await
        }

        packet_flags::cmd::aux::peer_cmd::SIGNAL => {
            let signal = PeerSignal::deserialize_from_vector(&payload[..]).ok()?;
            let timestamp = session.time_tracker.get_global_time_ns();
            let ticket = header.context_info.get().into();

            if !session.is_server {
                // forward the signal to the kernel, with some exceptions.
                match &signal {
                    PeerSignal::FcmTokenUpdate(new_keys) => {
                        // update local
                        let cnac = cnac.clone();
                        let persistence_handler = session.account_manager.get_persistence_handler().clone();
                        let to_kernel = session.kernel_tx.clone();
                        std::mem::drop(state_container);

                        persistence_handler.update_fcm_keys(&cnac, new_keys.clone()).await?;
                        to_kernel.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::SignalReceived(ticket), ticket))?;
                        return PrimaryProcessorResult::Void;
                    }

                    PeerSignal::Disconnect(vconn, resp) => {
                        let target = resp.as_ref().map(|_| vconn.get_original_implicated_cid()).unwrap_or(vconn.get_original_target_cid());
                        if let Some(v_conn) = state_container.active_virtual_connections.get(&target) {
                            v_conn.is_active.store(false, Ordering::SeqCst); //prevent further messages from being sent from this node
                            // ... but, we still want any messages already sent to be processed

                            let last_packet = v_conn.last_delivered_message_timestamp.clone();
                            let state_container_ref = session.state_container.clone();

                            std::mem::drop(state_container);

                            let task = async move {
                                loop {
                                    if let Some(ts) = last_packet.get() {
                                        if ts.elapsed() > Duration::from_millis(1500) {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }

                                    tokio::time::sleep(Duration::from_millis(1500)).await;
                                }

                                log::info!("[Peer Vconn] No packets received in the last 1500ms; will drop the connection cleanly");
                                // once we're done waiting for packets to stop showing up, we can remove the container to end the underlying TCP stream
                                let mut state_container = inner_mut!(state_container_ref);
                                let _ = state_container.active_virtual_connections.remove(&target);
                            };

                            let _ = spawn!(task);
                        } else {
                            log::warn!("Vconn already removed");
                        }

                        session.send_to_kernel(HdpServerResult::PeerEvent(signal, ticket))?;
                        return PrimaryProcessorResult::Void;
                    }

                    PeerSignal::DisconnectUDP(vconn) => {
                        let target_cid = get_resp_target_cid(vconn)?;
                        state_container.remove_udp_channel(target_cid);
                        return PrimaryProcessorResult::Void
                    }

                    PeerSignal::DeregistrationSuccess(peer_cid, used_fcm) => {
                        log::info!("[Deregistration] about to remove peer {} from {} at the endpoint", peer_cid, cnac.get_cid());
                        let acc_mgr = session.account_manager.clone();
                        let kernel_tx = session.kernel_tx.clone();
                        let cnac = cnac.clone();
                        let this_cid = cnac.get_cid();

                        if *used_fcm {
                            std::mem::drop(state_container);

                            let peer_cid = *peer_cid;
                            // now, send an FCM dereg signal. Then, create FCM dereg signal+handler. Finally, remove the kernel's dereg operation
                            match cnac.fcm_raw_send_to_peer(peer_cid, |fcm_ratchet| hyxe_user::external_services::fcm::fcm_packet_crafter::craft_deregistered(fcm_ratchet, peer_cid, ticket.0), acc_mgr.fcm_client()).await {
                                Ok(_) => {
                                    log::info!("Successfully alerted peer {} that deregistration occurred", peer_cid);
                                }

                                Err(err) => {
                                    log::warn!("Unable to alert peer {} that deregistration occurred: {:?}", peer_cid, err);
                                }
                            }
                        } else { // just remove the peer
                        }

                        if let None = acc_mgr.get_persistence_handler().deregister_p2p_as_client(this_cid, *peer_cid).await? {
                            log::warn!("Unable to remove hyperlan peer {}", peer_cid);
                        }

                        kernel_tx.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::Deregister(PeerConnectionType::HyperLANPeerToHyperLANPeer(cnac.get_cid(), *peer_cid), *used_fcm), ticket))?;
                        return PrimaryProcessorResult::Void
                    }

                    PeerSignal::PostRegister(vconn, a, b, peer_resp, FcmPostRegister::BobToAliceTransfer(transfer, fcm_keys, _cid)) => {
                        std::mem::drop(state_container);
                        // When using FCM, post-register requires syncing to the HD to establish static key pairs. Otherwise, normal post-registers do not since keys are re-established during post-connect stage
                        log::info!("[FCM] Received bob to alice transfer from {}", vconn.get_original_implicated_cid());
                        let peer_cid = vconn.get_original_implicated_cid();
                        let this_cid = vconn.get_original_target_cid();
                        // we need to get the peer kem state container
                        cnac.visit_mut(|mut inner| {
                            let mut fcm_constructor = inner.kem_state_containers.remove(&peer_cid)?.assume_fcm()?;
                            fcm_constructor.stage1_alice(transfer)?;
                            let fcm_ratchet = fcm_constructor.finish_with_custom_cid(this_cid)?;
                            let fcm_endpoint_container = PeerSessionCrypto::new_fcm(Toolset::new(this_cid, fcm_ratchet), true, fcm_keys.clone());
                            inner.fcm_crypt_container.insert(peer_cid, fcm_endpoint_container);
                            Some(())
                        })?;

                        let to_kernel = session.kernel_tx.clone();
                        let account_manager = session.account_manager.clone();
                        let cnac = cnac.clone();

                        if let Some(peer_resp_) = peer_resp.as_ref() {
                            match peer_resp_ {
                                PeerResponse::Accept(Some(peer_uname)) => {

                                    match account_manager.register_hyperlan_p2p_at_endpoints(this_cid, peer_cid, peer_uname).await {
                                        Ok(_) => {
                                            log::info!("[FCM] Successfully finished registration!");
                                            to_kernel.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::PostRegister(*vconn, a.clone(), b.clone(), peer_resp.clone(), FcmPostRegister::Enable), ticket))?;
                                            return PrimaryProcessorResult::Void;
                                        },

                                        Err(err) => {
                                            log::error!("Unable to register hyperlan p2p at endpoint: {:#?}", err);
                                        }
                                    }
                                }

                                _ => {}
                            }
                        }

                        cnac.save().await?;
                        log::info!("[FCM] Successfully finished registration!");
                        to_kernel.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::PostRegister(*vconn, a.clone(), b.clone(), peer_resp.clone(), FcmPostRegister::Enable), ticket))?;
                        return PrimaryProcessorResult::Void;
                    }

                    PeerSignal::PostRegister(vconn, _peer_username, ticket0, Some(PeerResponse::Accept(Some(peer_username))), FcmPostRegister::Disable) => {
                        let to_kernel = session.kernel_tx.clone();
                        let account_manager = session.account_manager.clone();

                        let peer_cid = vconn.get_original_implicated_cid();
                        let this_cid = vconn.get_original_target_cid();
                        std::mem::drop(state_container);

                        match account_manager.register_hyperlan_p2p_at_endpoints(this_cid, peer_cid, peer_username).await {
                            Ok(_) => {
                                log::info!("Success registering at endpoints");
                                to_kernel.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::PostRegister(*vconn, peer_username.clone(), *ticket0, Some(PeerResponse::Accept(Some(peer_username.clone()))), FcmPostRegister::Disable), ticket))?;
                            }

                            Err(err) => {
                                log::error!("Unable to register at endpoints: {:?}", &err);
                                to_kernel.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::SignalError(ticket, err.into_string()), ticket))?;
                            }
                        }

                        return PrimaryProcessorResult::Void;
                    }

                    PeerSignal::PostConnect(conn, _, resp, endpoint_security_settings, udp_enabled) => {
                        if let Some(resp) = resp {
                            // the connection was mutually accepted. Now, we must begin the KEM subroutine
                            match resp {
                                // the accept case
                                PeerResponse::Accept(_) => {
                                    return match conn {
                                        PeerConnectionType::HyperLANPeerToHyperLANPeer(original_implicated_cid, original_target_cid) => {
                                            // this implies this node is receiving an accept_request. As such, we need to NOT
                                            // forward the signal quite yet, and instead, begin the key-exchange process in order to
                                            // establish a working [PeerChannel] system that has a custom post-quantum key and toolset
                                            // unique to the session.
                                            //let mut state_container = inner_mut!(session.state_container);
                                            //let peer_cid = conn.get_original_implicated_cid();
                                            let mut peer_kem_state_container = PeerKemStateContainer::new(*endpoint_security_settings, *udp_enabled == UdpMode::Enabled);

                                            let alice_constructor = HyperRatchetConstructor::new_alice(ConstructorOpts::new_vec_init(Some(endpoint_security_settings.crypto_params), (endpoint_security_settings.security_level.value() + 1) as usize), conn.get_original_target_cid(), 0, Some(endpoint_security_settings.security_level));
                                            let transfer = alice_constructor.stage0_alice();
                                            //log::info!("0. Len: {}, {:?}", alice_pub_key.len(), &alice_pub_key[..10]);
                                            let msg_bytes = transfer.serialize_to_vec()?;
                                            peer_kem_state_container.constructor = Some(alice_constructor);
                                            state_container.peer_kem_states.insert(*original_implicated_cid, peer_kem_state_container);
                                            // finally, prepare the signal and send outbound
                                            // signal: PeerSignal, pqc: &Rc<PostQuantumContainer>, drill: &Drill, ticket: Ticket, timestamp: i64
                                            let signal = PeerSignal::Kem(PeerConnectionType::HyperLANPeerToHyperLANPeer(*original_target_cid, *original_implicated_cid), KeyExchangeProcess::Stage0(msg_bytes, *endpoint_security_settings, *udp_enabled));
                                            std::mem::drop(state_container);

                                            // use the pqc of the session to keep the data protected from here to the central
                                            // server and to the endpoint
                                            let hyper_ratchet = cnac.get_hyper_ratchet(None)?;

                                            let stage0_peer_kem = hdp_packet_crafter::peer_cmd::craft_peer_signal(&hyper_ratchet, signal, ticket, timestamp, security_level);
                                            log::info!("Sent peer KEM stage 0 outbound");
                                            // send to central server
                                            PrimaryProcessorResult::ReplyToSender(stage0_peer_kem)
                                        }

                                        _ => {
                                            log::error!("HyperWAN Functionality not yet enabled");
                                            PrimaryProcessorResult::Void
                                        }
                                    }
                                }

                                _ => {}
                            }
                        }
                    }

                    PeerSignal::Kem(conn, kep) => {
                        return match kep {
                            KeyExchangeProcess::Stage0(transfer, session_security_settings, udp_enabled) => {
                                log::info!("RECV STAGE 0 PEER KEM");
                                // We generate bob's pqc, as well as a nonce
                                //let mut state_container = inner_mut!(session.state_container);
                                //let this_cid = conn.get_original_target_cid();
                                let peer_cid = conn.get_original_implicated_cid();

                                let bob_constructor = HyperRatchetConstructor::new_bob(conn.get_original_target_cid(), 0, ConstructorOpts::new_vec_init(Some(session_security_settings.crypto_params), (session_security_settings.security_level.value() + 1) as usize), AliceToBobTransfer::deserialize_from(transfer)?)?;
                                let transfer = bob_constructor.stage0_bob()?;

                                let bob_transfer = transfer.serialize_to_vector().ok()?;

                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage1(bob_transfer, None));

                                let mut state_container_kem = PeerKemStateContainer::new(*session_security_settings, *udp_enabled == UdpMode::Enabled);
                                state_container_kem.constructor = Some(bob_constructor);
                                state_container.peer_kem_states.insert(peer_cid, state_container_kem);
                                // send signal
                                std::mem::drop(state_container);

                                let ref hyper_ratchet = session.cnac.get()?.get_hyper_ratchet(None)?;

                                let stage1_kem = hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, signal, ticket, timestamp, security_level);
                                log::info!("Sent stage 1 peer KEM");
                                PrimaryProcessorResult::ReplyToSender(stage1_kem)
                            }

                            KeyExchangeProcess::Stage1(transfer, Some(bob_nat_info)) => {
                                // Here, we finalize the creation of the pqc for alice, and then, generate the new toolset
                                // The toolset gets encrypted to ensure the central server doesn't see the toolset. This is
                                // to combat a "chinese communist hijack" scenario wherein a rogue government takes over our
                                // central servers
                                log::info!("RECV STAGE 1 PEER KEM");
                                //let security_level = session.security_level;
                                //let mut state_container = inner_mut!(session.state_container);
                                let peer_cid = conn.get_original_implicated_cid();
                                let this_cid = conn.get_original_target_cid();
                                let mut kem_state = state_container.peer_kem_states.remove(&peer_cid)?;
                                let session_security_settings = kem_state.session_security_settings;
                                let security_level = session_security_settings.security_level;
                                let mut alice_constructor = kem_state.constructor.take()?;
                                alice_constructor.stage1_alice(&BobToAliceTransferType::Default(BobToAliceTransfer::deserialize_from(transfer)?))?;
                                let hyper_ratchet = alice_constructor.finish_with_custom_cid(this_cid)?;
                                let endpoint_hyper_ratchet = hyper_ratchet.clone();
                                let endpoint_security_level = endpoint_hyper_ratchet.get_default_security_level();
                                // now, create a new toolset and encrypt it
                                // NOTE: when this toolset gets transmitted, it retains this_cid
                                // As such, the other end MUST change the CID internally for BOTH
                                // toolset AND the single drill
                                let toolset = Toolset::new(this_cid, hyper_ratchet);
                                // now, register the loaded PQC + toolset into the virtual conn
                                let peer_crypto = PeerSessionCrypto::new(toolset, true);
                                let vconn_type = VirtualConnectionType::HyperLANPeerToHyperLANPeer(this_cid, peer_cid);
                                let (needs_turn, bob_predicted_socket_addr) = bob_nat_info.generate_proper_listener_connect_addr(&session.local_nat_type);
                                log::info!("[STUN] Peer public addr: {:?} || needs TURN? {}", &bob_predicted_socket_addr, needs_turn);
                                let udp_rx_opt = kem_state.udp_channel_sender.rx.take();

                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(&mut *inner_mut!(session.updates_in_progress), bob_predicted_socket_addr, session_security_settings, ticket, peer_cid, vconn_type, peer_crypto);
                                // load the channel now that the keys have been exchanged

                                kem_state.local_is_initiator = true;
                                state_container.peer_kem_states.insert(peer_cid, kem_state);
                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);

                                let header_time = header.timestamp.get();
                                let (sync_instant, sync_time_ns) = calculate_sync_time(timestamp, header_time);
                                // now that the virtual connection is created on this end, we need to do the same to the other end
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage2(sync_time_ns, None));

                                let hole_punch_compat_stream = HolePunchCompatStream::new(session.to_primary_stream.clone()?, &mut *state_container, bob_nat_info.peer_remote_addr_visible_from_server, session.implicated_user_p2p_internal_listener_addr.clone()?, peer_cid, endpoint_hyper_ratchet.clone(), endpoint_security_level);
                                let hole_puncher = UdpHolePuncher::new(hole_punch_compat_stream, RelativeNodeType::Initiator, generate_hole_punch_crypt_container(endpoint_hyper_ratchet, SecurityLevel::LOW, peer_cid));

                                std::mem::drop(state_container);
                                // we need to use the session pqc since this signal needs to get processed by the center node
                                let ref sess_hyper_ratchet = session.cnac.get()?.get_hyper_ratchet(None)?;
                                let stage2_kem_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(sess_hyper_ratchet, signal, ticket, timestamp, security_level);
                                log::info!("Sent stage 2 peer KEM");

                                // now, fire-up the hole-punch future
                                let implicated_cid = session.implicated_cid.clone();
                                let kernel_tx = session.kernel_tx.clone();
                                session.send_to_primary_stream(None, stage2_kem_packet)?;
                                //session.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt)).ok()?;
                                let channel_signal = HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt);
                                let quic_endpoint = session.client_only_quic_endpoint.clone()?;
                                let hole_punch_future = attempt_simultaneous_hole_punch(conn.reverse(), ticket, session_orig.clone(), bob_nat_info.clone(), implicated_cid, kernel_tx, channel_signal, sync_instant, session.state_container.clone(), endpoint_security_level, hole_puncher, quic_endpoint);
                                let _ = spawn!(hole_punch_future);

                                //let _ = hole_punch_future.await;
                                PrimaryProcessorResult::Void
                            }

                            KeyExchangeProcess::Stage2(sync_time_ns, Some(alice_nat_info)) => {
                                // NEW UPDATE: now that we know the other side successfully created its toolset,
                                // calculate sync time then begin the hole punch subroutine
                                log::info!("RECV STAGE 2 PEER KEM");
                                let peer_cid = conn.get_original_implicated_cid();
                                let this_cid = conn.get_original_target_cid();
                                //let security_level = session.security_level;
                                //let mut state_container = inner_mut!(session.state_container);
                                let kem = state_container.peer_kem_states.get_mut(&peer_cid)?;
                                let session_security_settings = kem.session_security_settings;
                                // since the AES-GCM was a success, we can now entrust that the toolset is perfectly symmetric to the
                                // other side's toolset
                                let bob_constructor = kem.constructor.take()?;
                                let udp_rx_opt = kem.udp_channel_sender.rx.take();
                                let endpoint_hyper_ratchet = bob_constructor.finish_with_custom_cid(this_cid)?;
                                //let endpoint_security_level = endpoint_hyper_ratchet.get_default_security_level();
                                let endpoint_security_level = session_security_settings.security_level;
                                let toolset = Toolset::new(this_cid, endpoint_hyper_ratchet.clone());
                                let peer_crypto = PeerSessionCrypto::new(toolset, false);

                                // create an endpoint vconn
                                let vconn_type = VirtualConnectionType::HyperLANPeerToHyperLANPeer(this_cid, peer_cid);
                                let (needs_turn, alice_predicted_socket_addr) = alice_nat_info.generate_proper_listener_connect_addr(&session.local_nat_type);
                                log::info!("[STUN] Peer public addr: {:?} || needs TURN? {}", &alice_predicted_socket_addr, needs_turn);
                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(&mut *inner_mut!(session.updates_in_progress),alice_predicted_socket_addr, session_security_settings, ticket, peer_cid, vconn_type, peer_crypto);

                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);
                                // We can now send the channel to the kernel, where TURN traversal is immediantly available.
                                // however, STUN-like traversal will proceed in the background
                                //state_container.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt)).ok()?;
                                let hole_punch_compat_stream = HolePunchCompatStream::new(session.to_primary_stream.clone()?, &mut *state_container, alice_nat_info.peer_remote_addr_visible_from_server, session.implicated_user_p2p_internal_listener_addr.clone()?, peer_cid, endpoint_hyper_ratchet.clone(), endpoint_security_level);
                                let hole_puncher = UdpHolePuncher::new(hole_punch_compat_stream, RelativeNodeType::Receiver, generate_hole_punch_crypt_container(endpoint_hyper_ratchet, SecurityLevel::LOW, peer_cid));
                                let channel_signal = HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt);
                                let diff = Duration::from_nanos(i64::abs(timestamp - *sync_time_ns) as u64);
                                let sync_instant = Instant::now() + diff;

                                // session: HdpSession, expected_peer_cid: u64, peer_endpoint_addr: SocketAddr, implicated_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, sync_time: Instant
                                let implicated_cid = session.implicated_cid.clone();
                                let kernel_tx = session.kernel_tx.clone();
                                let quic_endpoint = session.client_only_quic_endpoint.clone()?;
                                let hole_punch_future = attempt_simultaneous_hole_punch(conn.reverse(), ticket, session_orig.clone(), alice_nat_info.clone(), implicated_cid, kernel_tx.clone(), channel_signal, sync_instant, session.state_container.clone(), endpoint_security_level, hole_puncher, quic_endpoint);
                                std::mem::drop(state_container);
                                let _ = spawn!(hole_punch_future);

                                //let _ = hole_punch_future.await;
                                PrimaryProcessorResult::Void
                            }

                            KeyExchangeProcess::HolePunchEstablished => {
                                log::info!("RECV HolePunchEstablished packet");
                                // The other side (client) is telling us it made a connection. It still is waiting on this node to verify
                                // that the connection is valid. What we do here is set p2p_conn as established.
                                // We only upgrade IF local is NOT the initiator. Because if the opposite end IS the initiator,
                                // then it gets to keep its connection no matter the result of this end's attempt to connect.
                                // If the local IS the initiator, then don't upgrade quite yet. We need to wait to make sure the
                                // other end finishes. In either case, we set the p2p conn as established
                                let peer_cid = conn.get_original_implicated_cid();
                                let kem_state_container = state_container.peer_kem_states.get_mut(&peer_cid)?;

                                let possible_verified_conn = kem_state_container.verified_socket_addr.clone();
                                kem_state_container.p2p_conn_established = true;
                                let local_is_initiator = kem_state_container.local_is_initiator;
                                let mut upgraded_connection = false;
                                if !local_is_initiator {
                                    // We upgrade the connection
                                    if let Ok(udp_conn) = state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                        log::info!("Successfully upgraded direct p2p connection for {}@{:?}", peer_cid, peer_addr);

                                        if let Some(udp_conn) = udp_conn {
                                            let hole_punched_addr = HolePunchedSocketAddr::new(peer_addr, peer_addr, Default::default());
                                            HdpSession::udp_socket_loader(session.clone(), conn.reverse().as_virtual_connection(), UdpSplittableTypes::QUIC(udp_conn), hole_punched_addr, ticket, None);
                                        }

                                        upgraded_connection = true;
                                    } else {
                                        log::warn!("Unable to upgrade direct P2P connection for {:?}. Missing items?", peer_addr);
                                        return PrimaryProcessorResult::Void;
                                    }
                                } else {
                                    // upgrade-on-drop option IF local doesn't have conn established
                                    state_container.provisional_direct_p2p_conns.get_mut(&peer_addr)?.fallback = Some(peer_cid);
                                    log::info!("[Fallback] Will use the stream w/ {:?} if the other does not succeed in valid time", peer_addr);
                                }

                                // Now, tell the other side the connection was established. Here, we use just pqc and drill because this packet,
                                // by requirement, was encrypted using the endpoint encryption
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::HolePunchEstablishedVerified(upgraded_connection));
                                let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal_endpoint(&sess_hyper_ratchet, signal, ticket, timestamp, peer_cid, security_level);
                                PrimaryProcessorResult::ReplyToSender(packet)
                            }

                            KeyExchangeProcess::HolePunchEstablishedVerified(upgraded_connection) => {
                                log::info!("RECV HolePunchEstablishedVerified packet");
                                let peer_cid = conn.get_original_implicated_cid();
                                // this node made it across the NAT. But, we don't necessarily upgrade the connection unless
                                // upgraded_connection is true (in which case, the other side upgraded their connection)
                                let kem_state_container = state_container.peer_kem_states.get_mut(&peer_cid)?;
                                let local_is_initiator = kem_state_container.local_is_initiator;
                                let other_conn_established = kem_state_container.p2p_conn_established;
                                let possible_verified_conn = kem_state_container.verified_socket_addr.clone();

                                if *upgraded_connection {
                                    // upgrade the connection no matter what
                                    debug_assert!(local_is_initiator);
                                    log::info!("This exact connection has been upgraded by the adjacent node, Doing the same locally ...");
                                    if let Ok(udp_conn) = state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                        log::info!("Successfully upgraded direct p2p connection for {}@{:?}. Process complete!", peer_cid, peer_addr);
                                        if let Some(udp_conn) = udp_conn {
                                            let hole_punched_addr = HolePunchedSocketAddr::new(peer_addr, peer_addr, Default::default());
                                            HdpSession::udp_socket_loader(session.clone(), conn.reverse().as_virtual_connection(), UdpSplittableTypes::QUIC(udp_conn), hole_punched_addr, ticket, None);
                                        }
                                    } else {
                                        log::warn!("Unable to upgrade direct P2P connection for {:?}. Missing items?", peer_addr);
                                    }
                                } else {
                                    debug_assert!(!local_is_initiator);
                                    // Since this connection works, but the other side didn't upgrade it, that means that
                                    // we are waiting for the initiator's attempt to finish. But, if other_conn_established,
                                    // then the connection happened which means we can drop this connection.
                                    if other_conn_established {
                                        log::info!("Other connection established. Will drop this exact connection");
                                        // since these packets come thru the p2p streams, ending the session will only end the p2p session
                                        return PrimaryProcessorResult::EndSession("Other connection established. Will drop this exact connection");
                                    } else {
                                        // since this connection works, but the other connection has not been established, we need to wait for it
                                        // to send this node a HolePunchEstablished. This stream will get dropped if a
                                        // HolePunchEstablished arrives (since the other stream belongs to the initiator, and this one does not).
                                        // During the upgrade process, since this stream would get overwritten if the initiator stream goes-in,
                                        // we will upgrade the connection for now
                                        kem_state_container.verified_socket_addr = Some(peer_addr);
                                        log::info!("Connection established, but is a non-initiator stream. Will upgrade, but may be overwritten in the interim");
                                        if let Ok(udp_conn) = state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                            log::info!("Successfully upgraded direct p2p connection for {}@{:?}. May be overwritten though ...", peer_cid, peer_addr);

                                            if let Some(udp_conn) = udp_conn {
                                                let hole_punched_addr = HolePunchedSocketAddr::new(peer_addr, peer_addr, Default::default());
                                                HdpSession::udp_socket_loader(session.clone(), conn.reverse().as_virtual_connection(), UdpSplittableTypes::QUIC(udp_conn), hole_punched_addr, ticket, None);
                                            }
                                        } else {
                                            log::warn!("Unable to upgrade direct P2P connection for {:?}. Missing items? (provisional)", peer_addr);
                                        }
                                    }
                                }

                                PrimaryProcessorResult::Void
                            }

                            KeyExchangeProcess::HolePunchFailed => {
                                log::info!("RECV HolePunchFailed");
                                // TODO/optional: for future consideration, but is currently not at all necessary
                                PrimaryProcessorResult::Void
                            }

                            _ => {
                                log::error!("INVALID KEM signal");
                                PrimaryProcessorResult::Void
                            }
                        };
                    }

                    _ => {}
                }

                log::info!("Forwarding PEER signal to kernel ...");
                session.kernel_tx.unbounded_send(HdpServerResult::PeerEvent(signal, ticket))?;
                PrimaryProcessorResult::Void
            } else {
                std::mem::drop(state_container);

                process_signal_command_as_server(session_orig, signal, ticket, sess_hyper_ratchet, header, timestamp, security_level).await
            }
        }

        packet_flags::cmd::aux::peer_cmd::CHANNEL => {
            PrimaryProcessorResult::Void
        }

        _ => {
            log::error!("Invalid peer auxiliary command");
            PrimaryProcessorResult::Void
        }
    }
}


async fn process_signal_command_as_server(sess_ref: &HdpSession, signal: PeerSignal, ticket: Ticket, sess_hyper_ratchet: HyperRatchet, header: LayoutVerified<&[u8], HdpHeader>, timestamp: i64, security_level: SecurityLevel) -> PrimaryProcessorResult {
    let session = sess_ref;
    match signal {
        PeerSignal::Kem(conn, mut kep) => {
            // before just routing the signals, we also need to add socket information into intercepted stage1 and stage2 signals
            // to allow for STUN-like NAT traversal
            // this gives peer A the socket of peer B and vice versa

            let peer_nat = session.adjacent_nat_type.clone()?;
            let peer_internal_listener_addr = session.implicated_user_p2p_internal_listener_addr.clone()?;
            let peer_remote_addr_visible_from_server = session.remote_peer;
            let tls_domain = session.peer_only_connect_protocol.get()?.get_domain();

            let peer_nat_info = PeerNatInfo {
                peer_remote_addr_visible_from_server,
                peer_internal_listener_addr,
                peer_nat,
                tls_domain
            };

            match &mut kep {
                KeyExchangeProcess::Stage1(_, val) | KeyExchangeProcess::Stage2(_, val) => {
                    *val = Some(peer_nat_info);
                }

                _ => {}
            }

            // since this is the server, we just need to route this to the target_cid
            let sess_mgr = inner!(session.session_manager);
            let signal_to = PeerSignal::Kem(conn, kep);
            if sess_hyper_ratchet.get_cid() == conn.get_original_target_cid() {
                log::error!("Error X678");
                return PrimaryProcessorResult::Void;
            }

            let res = sess_mgr.send_signal_to_peer_direct(conn.get_original_target_cid(), move |peer_hyper_ratchet| {
                hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal_to, ticket, timestamp, security_level)
            });

            if let Err(err) = res {
                reply_to_sender_err(err, &sess_hyper_ratchet, ticket, timestamp, security_level)
            } else {
                PrimaryProcessorResult::Void
            }
        }

        PeerSignal::PostRegister(peer_conn_type, username, _ticket_opt, peer_response, fcm) => {
            // check to see if the client is connected, and if not, send to HypernodePeerLayer
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => {
                    let implicated_cid = header.session_cid.get();
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour
                    // if the peer response is some, then HyperLAN Client B responded
                    if let Some(peer_response) = peer_response {
                        match fcm {
                            tx @ FcmPostRegister::BobToAliceTransfer(..) | tx @ FcmPostRegister::Decline => {
                                // Now, register the two account together
                                let sess_mgr = session.session_manager.clone();
                                let decline = tx == FcmPostRegister::Decline;
                                let account_manager = session.account_manager.clone();

                                if !decline {
                                    if let Err(err) = account_manager.register_hyperlan_p2p_as_server(peer_conn_type.get_original_implicated_cid(), peer_conn_type.get_original_target_cid()).await {
                                        return reply_to_sender_err(err.into_string(), &sess_hyper_ratchet, ticket, timestamp, security_level);
                                    }
                                }

                                let res = sess_mgr.clone().fcm_post_register_to(header.session_cid.get(), peer_conn_type.get_original_target_cid(), true, move |static_hr| { hyxe_user::external_services::fcm::fcm_packet_crafter::craft_post_register(static_hr, ticket.0, implicated_cid, tx, username) },
                                                                                move |res| {
                                                                                           post_fcm_send(res, sess_mgr.clone(), ticket, implicated_cid, security_level)
                                                                                       }).await;

                                match res {
                                    Ok(_) => {
                                        // response will occur in the future via on_send_complete
                                        PrimaryProcessorResult::Void
                                    }

                                    Err(err) => {
                                        log::warn!("Unable to return accept/deny request packet: {:?}", &err);
                                        reply_to_sender_err(err.into_string(), &sess_hyper_ratchet, ticket, timestamp, security_level)
                                    }
                                }
                            }

                            _ => {
                                // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                                let decline = match &peer_response { PeerResponse::Decline => true, _ => false };

                                route_signal_response(PeerSignal::PostRegister(peer_conn_type, username.clone(), Some(ticket), Some(peer_response), fcm), implicated_cid, target_cid, timestamp, ticket, session.clone(), &sess_hyper_ratchet,
                                                      |this_sess, _peer_sess, _original_tracked_posting| {
                                                          if !decline {
                                                              let account_manager = this_sess.account_manager.clone();
                                                              let task = async move {
                                                                  if let Err(err) = account_manager.register_hyperlan_p2p_as_server(implicated_cid, target_cid).await {
                                                                      log::error!("Unable to register hyperlan p2p at server: {:?}", err);
                                                                  }
                                                              };

                                                              let _ = tokio::task::spawn(task);
                                                          }
                                                      }, security_level)
                            }
                        }
                    } else {
                        // We route the signal from alice to bob. We send directly to Bob if FCM is not specified. If FCM is being used, then will route to target's FCM credentials
                        match &fcm {
                            FcmPostRegister::AliceToBobTransfer(..) => {
                                let implicated_cid = header.session_cid.get();
                                let sess_mgr = session.session_manager.clone(); // we must clone since the session may end after the FCM send occurs. We don't want to hold a strong ref

                                let res = sess_mgr.clone().fcm_post_register_to(implicated_cid, target_cid, false, move |static_hr| { hyxe_user::external_services::fcm::fcm_packet_crafter::craft_post_register(static_hr, ticket.0, implicated_cid, fcm, username) }, move |res| {
                                    post_fcm_send(res, sess_mgr, ticket, implicated_cid, security_level)
                                }).await;

                                match res {
                                    Ok(_) => {
                                        // We won't reply until AFTER the fcm message send
                                        PrimaryProcessorResult::Void
                                    }

                                    Err(err) => {
                                        log::warn!("Unable to post-register: {:?}", &err);
                                        reply_to_sender_err(err.into_string(), &sess_hyper_ratchet, ticket, timestamp, security_level)
                                    }
                                }
                            }

                            _ => {
                                // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase). No FCM
                                let to_primary_stream = session.to_primary_stream.clone()?;
                                let sess_mgr = session.session_manager.clone();
                                route_signal_and_register_ticket_forwards(PeerSignal::PostRegister(peer_conn_type, username, Some(ticket), None, fcm), TIMEOUT, implicated_cid, target_cid, timestamp, ticket, &to_primary_stream, &sess_mgr, &sess_hyper_ratchet, security_level).await
                            }
                        }
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    log::warn!("HyperWAN functionality not implemented");
                    PrimaryProcessorResult::Void
                }
            }
        }

        PeerSignal::Deregister(peer_conn_type, use_fcm) => {
            // in deregistration, we send a Deregister signal to the peer (if connected)
            // then, delete the cid entry from the CNAC and save to the local FS
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let cnac = session.cnac.get()?;
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    if cnac.get_id() == implicated_cid {
                        match account_manager.deregister_hyperlan_p2p_as_server(implicated_cid, target_cid).await {
                            Ok(_) => {
                                // route the original signal to the other end. If not connected, don't bother
                                // FCM note: the endpoint's duty is to send an FCM signal before completing deregistration
                                let peer_alert_signal = PeerSignal::DeregistrationSuccess(implicated_cid, use_fcm);
                                if !session_manager.send_signal_to_peer(target_cid, ticket, peer_alert_signal, timestamp, security_level) {
                                    log::warn!("Unable to send packet to {} (maybe not connected)", target_cid);
                                }

                                // now, send a success packet to the client
                                let success_cmd = PeerSignal::DeregistrationSuccess(target_cid, use_fcm);
                                let rebound_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(&sess_hyper_ratchet, success_cmd, ticket, timestamp, security_level);
                                PrimaryProcessorResult::ReplyToSender(rebound_packet)
                            }

                            Err(err) => {
                                // unable to find the peer
                                let error_signal = PeerSignal::SignalError(ticket, err.into_string());
                                let error_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(&sess_hyper_ratchet, error_signal, ticket, timestamp, security_level);
                                PrimaryProcessorResult::ReplyToSender(error_packet)
                            }
                        }
                    } else {
                        PrimaryProcessorResult::Void
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    log::warn!("HyperWAN functionality not yet enabled");
                    PrimaryProcessorResult::Void
                }
            }
        }

        PeerSignal::PostConnect(peer_conn_type, _ticket_opt, peer_response, endpoint_security_level, udp_enabled) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60);
                    if let Some(peer_response) = peer_response {
                        // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                        route_signal_response(PeerSignal::PostConnect(peer_conn_type, Some(ticket), Some(peer_response), endpoint_security_level, udp_enabled), implicated_cid, target_cid, timestamp, ticket, session.clone(), &sess_hyper_ratchet,
                                              |this_sess, peer_sess, _original_tracked_posting| {
                                                  // when the route finishes, we need to update both sessions to allow high-level message-passing
                                                  // In other words, forge a virtual connection
                                                  // In order for routing of packets to be fast, we need to get the direct handles of the stream
                                                  // placed into the state_containers
                                                  if let Some(this_tcp_sender) = this_sess.to_primary_stream.clone() {
                                                      if let Some(peer_tcp_sender) = peer_sess.to_primary_stream.clone() {
                                                          let mut this_sess_state_container = inner_mut!(this_sess.state_container);
                                                          let mut peer_sess_state_container = inner_mut!(peer_sess.state_container);

                                                          // The UDP senders may not exist (e.g., TCP only mode)
                                                          let this_udp_sender = this_sess_state_container.udp_primary_outbound_tx.clone();
                                                          let peer_udp_sender = peer_sess_state_container.udp_primary_outbound_tx.clone();
                                                          // rel to this local sess, the key = target_cid, then (implicated_cid, target_cid)
                                                          let virtual_conn_relative_to_this = VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid);
                                                          let virtual_conn_relative_to_peer = VirtualConnectionType::HyperLANPeerToHyperLANPeer(target_cid, implicated_cid);
                                                          this_sess_state_container.insert_new_virtual_connection_as_server(target_cid, virtual_conn_relative_to_this, peer_udp_sender, peer_tcp_sender);
                                                          peer_sess_state_container.insert_new_virtual_connection_as_server(implicated_cid, virtual_conn_relative_to_peer, this_udp_sender, this_tcp_sender);
                                                          log::info!("Virtual connection between {} <-> {} forged", implicated_cid, target_cid);
                                                          // TODO: Ensure that, upon disconnect, the the corresponding entry gets dropped in the connection table of not the dropped peer
                                                      }
                                                  }
                                              }, security_level)
                    } else {
                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase)
                        let to_primary_stream = session.to_primary_stream.clone()?;
                        let sess_mgr = session.session_manager.clone();

                        route_signal_and_register_ticket_forwards(PeerSignal::PostConnect(peer_conn_type, Some(ticket), None, endpoint_security_level, udp_enabled), TIMEOUT, implicated_cid, target_cid, timestamp, ticket, &to_primary_stream, &sess_mgr,  &sess_hyper_ratchet, security_level).await
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    log::error!("HyperWAN functionality not implemented");
                    return PrimaryProcessorResult::Void;
                }
            }
        }

        PeerSignal::Disconnect(peer_conn_type, resp) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let state_container = inner!(session.state_container);
                    if let Some(v_conn) = state_container.active_virtual_connections.get(&target_cid) {
                        v_conn.is_active.store(false, Ordering::SeqCst); //prevent further messages from being sent from this node
                        // ... but, we still want any messages already sent to be processed

                        let last_packet = v_conn.last_delivered_message_timestamp.clone();
                        let state_container_ref = session.state_container.clone();
                        let session_manager = session.session_manager.clone();
                        let outbound_tx = return_if_none!(session.to_primary_stream.clone(), "Outbound sender not loaded");

                        std::mem::drop(state_container);

                        let task = async move {
                            loop {
                                if let Some(ts) = last_packet.get() {
                                    if ts.elapsed() > Duration::from_millis(1500) {
                                        break;
                                    }
                                } else {
                                    break;
                                }

                                tokio::time::sleep(Duration::from_millis(1500)).await;
                            }

                            log::info!("[Peer Vconn @ Server] No packets received in the last 1500ms; will drop the virtual connection cleanly");
                            // once we're done waiting for packets to stop showing up, we can remove the container to end the underlying TCP stream
                            let mut state_container = inner_mut!(state_container_ref);
                            let _ = state_container.active_virtual_connections.remove(&target_cid);

                            let resp = Some(resp.unwrap_or(PeerResponse::Disconnected(format!("Peer {} closed the virtual connection to {}", implicated_cid, target_cid))));
                            let signal_to_peer = PeerSignal::Disconnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid), resp);
                            // now, remove target CID's v_conn to `implicated_cid`
                            std::mem::drop(state_container);
                            let res = session_manager.disconnect_virtual_conn(implicated_cid, target_cid, move |peer_hyper_ratchet| {
                                // send signal to peer
                                hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal_to_peer, ticket, timestamp, security_level)
                            });

                            // now, send a packet back to the source
                            match res.map_or_else(|err| reply_to_sender_err(err, &sess_hyper_ratchet, ticket, timestamp, security_level),
                                            |_| reply_to_sender(PeerSignal::Disconnect(peer_conn_type, None), &sess_hyper_ratchet, ticket, timestamp, security_level)) {
                                PrimaryProcessorResult::ReplyToSender(packet) => {
                                    if let Err(err) = outbound_tx.unbounded_send(packet) {
                                        log::error!("Unable to send to outbound stream: {:?}", err);
                                    }
                                }

                                _ => {}
                            }
                        };

                        let _ = spawn!(task);

                        PrimaryProcessorResult::Void
                    } else {
                        //reply_to_sender_err(format!("{} is not connected to {}", implicated_cid, target_cid), &sess_hyper_ratchet, ticket, timestamp, security_level)
                        // connection may already be dc'ed from another dc attempt. Just say nothing
                        PrimaryProcessorResult::Void
                    }
                }

                _ => {
                    log::error!("HyperWAN functionality not implemented");
                    return PrimaryProcessorResult::Void;
                }
            }
        }

        PeerSignal::GetRegisteredPeers(hypernode_conn_type, _resp_opt, limit) => {
            match hypernode_conn_type {
                HypernodeConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    log::info!("[GetRegisteredPeers] Getting list");
                    let rebound_signal = if let Some(registered_local_clients) = account_manager.get_registered_impersonal_cids(limit).await? {
                        // TODO: Make check_online_status check database for database mode
                        let online_status = session_manager.check_online_status(&registered_local_clients);
                        PeerSignal::GetRegisteredPeers(hypernode_conn_type, Some(PeerResponse::RegisteredCids(registered_local_clients, online_status)), limit)
                    } else {
                        PeerSignal::GetRegisteredPeers(hypernode_conn_type, None, limit)
                    };

                    log::info!("[GetRegisteredPeers] Done getting list");
                    reply_to_sender(rebound_signal, &sess_hyper_ratchet, ticket, timestamp, security_level)
                }

                HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    log::error!("HyperWAN functionality not implemented");
                    return PrimaryProcessorResult::Void;
                }
            }
        }

        PeerSignal::GetMutuals(hypernode_conn_type, _resp_opt) => {
            match hypernode_conn_type {
                HypernodeConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    log::info!("[GetMutuals] Getting list");
                    let rebound_signal = if let Some(mutuals) = account_manager.get_hyperlan_peer_list(implicated_cid).await? {
                        let online_status = session_manager.check_online_status(&mutuals);
                        PeerSignal::GetMutuals(hypernode_conn_type, Some(PeerResponse::RegisteredCids(mutuals, online_status)))
                    } else {
                        PeerSignal::GetMutuals(hypernode_conn_type, None)
                    };

                    log::info!("[GetMutuals] Done getting list");
                    reply_to_sender(rebound_signal, &sess_hyper_ratchet, ticket, timestamp, security_level)
                }

                HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    log::error!("HyperWAN functionality not implemented");
                    PrimaryProcessorResult::Void
                }
            }
        }

        PeerSignal::BroadcastConnected(_hypernode_conn_type) => {
            PrimaryProcessorResult::Void
        }

        PeerSignal::PostFileUploadRequest(_peer_conn_type, _file_metadata, _ticket) => {
            PrimaryProcessorResult::Void
        }

        PeerSignal::AcceptFileUploadRequest(_peer_conn_type, _ticket) => {
            PrimaryProcessorResult::Void
        }

        PeerSignal::SignalError(ticket, err) => {
            // in this case, we delegate the error to the higher-level kernel to determine what to do
            session.kernel_tx.unbounded_send(HdpServerResult::PeerEvent(PeerSignal::SignalError(ticket, err), ticket))?;
            PrimaryProcessorResult::Void
        }

        PeerSignal::SignalReceived(ticket) => {
            session.kernel_tx.unbounded_send(HdpServerResult::PeerEvent(signal, ticket))?;
            PrimaryProcessorResult::Void
        }

        PeerSignal::DeregistrationSuccess(..) => {
            PrimaryProcessorResult::Void
        }

        PeerSignal::DisconnectUDP(v_conn) => {
            // close this UDP channel
            inner_mut!(session.state_container).remove_udp_channel(v_conn.get_target_cid());
            PrimaryProcessorResult::Void
        }

        PeerSignal::Fcm(fcm_ticket, raw_fcm_packet) => {
            // since we are at the server, the raw fcm packet can't be accessed. We only need to store the packet inside
            let account_manager = session.account_manager.clone();

            if let Some(recipient_cnac) = account_manager.get_client_by_cid(fcm_ticket.target_cid).await? {
                match recipient_cnac.store_raw_fcm_packet_into_recipient(fcm_ticket, raw_fcm_packet).await {
                    Ok(_) => {
                        reply_to_sender(PeerSignal::SignalReceived(ticket), &sess_hyper_ratchet, ticket, timestamp, security_level)
                    }

                    Err(err) => {
                        reply_to_sender_err(err.into_string(), &sess_hyper_ratchet, ticket, timestamp, security_level)
                    }
                }
            } else {
                reply_to_sender_err(format!("Peer {} does not exist on this server", fcm_ticket.target_cid), &sess_hyper_ratchet, ticket, timestamp, security_level)
            }
        }

        PeerSignal::FcmFetch(..) => {
            // TODO: This will be invalid since it doesn't poll the backend
            let ref cnac = session.cnac.get()?;

            reply_to_sender(PeerSignal::FcmFetch(cnac.retrieve_raw_fcm_packets().await?), &sess_hyper_ratchet, ticket, timestamp, security_level)
        }

        PeerSignal::FcmTokenUpdate(new_keys) => {
            let _implicated_cid = header.session_cid.get();
            let account_manager = session.account_manager.clone();
            let tt = session.time_tracker.clone();
            let ref cnac = session.cnac.get()?;

            let res = account_manager.get_persistence_handler().update_fcm_keys(&cnac, new_keys.clone()).await;
            let timestamp = tt.get_global_time_ns();
            match res {
                Ok(_) => {
                    reply_to_sender(PeerSignal::FcmTokenUpdate(new_keys), &sess_hyper_ratchet, ticket, timestamp, security_level)
                }

                Err(err) => {
                    reply_to_sender_err(err.into_string(), &sess_hyper_ratchet, ticket, timestamp, security_level)
                }
            }
        }
    }
}

#[inline]
/// This just makes the repeated operation above cleaner. By itself does not send anything; must return the result of this closure directly
fn reply_to_sender(signal: PeerSignal, hyper_ratchet: &HyperRatchet, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> PrimaryProcessorResult {
    let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, signal, ticket, timestamp, security_level);
    PrimaryProcessorResult::ReplyToSender(packet)
}

fn reply_to_sender_via_primary_stream(packet: BytesMut, primary_stream: &OutboundPrimaryStreamSender) {
    if let Err(err) = primary_stream.unbounded_send(packet) {
        log::warn!("Unable to send to primary stream: {:?}", err);
    } else {
        log::info!("Successfully sent to primary stream");
    }
}

#[inline]
fn reply_to_sender_err<E: ToString>(err: E, hyper_ratchet: &HyperRatchet, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> PrimaryProcessorResult {
    PrimaryProcessorResult::ReplyToSender(construct_error_signal(err, hyper_ratchet, ticket, timestamp, security_level))
}

fn construct_error_signal<E: ToString>(err: E, hyper_ratchet: &HyperRatchet, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
    let err_signal = PeerSignal::SignalError(ticket, err.to_string());
    hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, err_signal, ticket, timestamp, security_level)
}

async fn route_signal_and_register_ticket_forwards(signal: PeerSignal, timeout: Duration, implicated_cid: u64, target_cid: u64, timestamp: i64, ticket: Ticket, to_primary_stream: &OutboundPrimaryStreamSender, sess_mgr: &HdpSessionManager, sess_hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> PrimaryProcessorResult {
    let sess_hyper_ratchet_2 = sess_hyper_ratchet.clone();
    let to_primary_stream = to_primary_stream.clone();

    // Give the target_cid 10 seconds to respond
    let res = sess_mgr.route_signal_primary(implicated_cid, target_cid, ticket, signal.clone(), move |peer_hyper_ratchet| {
        hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal.clone(), ticket, timestamp, security_level)
    }, timeout, move |stale_signal| {
        // on timeout, run this
        log::warn!("Running timeout closure. Sending error message to {}", implicated_cid);
        let error_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(&sess_hyper_ratchet_2, stale_signal, ticket, timestamp, security_level);
        let _ = to_primary_stream.unbounded_send(error_packet);
    }).await;

    // Then, we tell the implicated_cid's node that we have handled the message. However, the peer has yet to respond
    if let Err(err) = res {
        reply_to_sender_err(err, sess_hyper_ratchet, ticket, timestamp, security_level)
    } else {
        let received_signal = PeerSignal::SignalReceived(ticket);
        reply_to_sender(received_signal, sess_hyper_ratchet, ticket, timestamp, security_level)
    }
}

// returns (true, status) if the process was a success, or (false, success) otherwise
fn route_signal_response(signal: PeerSignal, implicated_cid: u64, target_cid: u64, timestamp: i64, ticket: Ticket, session: HdpSession, sess_hyper_ratchet: &HyperRatchet, on_route_finished: impl FnOnce(&HdpSession, &HdpSession, PeerSignal), security_level: SecurityLevel) -> PrimaryProcessorResult {
    let sess_mgr = session.session_manager.clone();
    let sess_mgr = inner!(sess_mgr);
    log::info!("impl: {} | target: {}", implicated_cid, target_cid);

    let res = sess_mgr.route_signal_response_primary(implicated_cid, target_cid, ticket, move |peer_hyper_ratchet| {
        hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal, ticket, timestamp, security_level)
    }, move |peer_sess, original_posting| {
        // send a notification that the server forwarded the signal
        let received_signal = PeerSignal::SignalReceived(ticket);
        let ret = reply_to_sender(received_signal, sess_hyper_ratchet, ticket, timestamp, security_level);
        log::info!("Running on_route_finished subroutine");
        //let mut peer_sess_ref = inner_mut!(peer_sess);
        on_route_finished(&session, peer_sess, original_posting);
        ret
    });

    match res {
        Ok(ret) => {
            ret
        }

        Err(err) => {
            reply_to_sender_err(err, &sess_hyper_ratchet, ticket, timestamp, security_level)
        }
    }
}

fn post_fcm_send(res: Result<(), AccountError>, session_manager: HdpSessionManager, ticket: Ticket, implicated_cid: u64, security_level: SecurityLevel) {
    log::info!("[FCM] Done sending FCM message");
    // After the send is complete, we go here
    if let Some(sess) = session_manager.get_session_by_cid(implicated_cid) {
        let timestamp = sess.time_tracker.get_global_time_ns();
        if let Some(primary_stream) = sess.to_primary_stream.as_ref() {
            if let Some(ref cnac) = sess.cnac.get() {
                let latest_hr = cnac.get_hyper_ratchet(None).unwrap();
                let packet = match res {
                    Ok(_) => {
                        hdp_packet_crafter::peer_cmd::craft_peer_signal(&latest_hr, PeerSignal::SignalReceived(ticket), ticket, timestamp, security_level)
                    }

                    Err(err) => {
                        hdp_packet_crafter::peer_cmd::craft_peer_signal(&latest_hr, PeerSignal::SignalError(ticket, err.into_string()), ticket, timestamp, security_level)
                    }
                };

                reply_to_sender_via_primary_stream(packet, primary_stream);
            }
        }
    }
}