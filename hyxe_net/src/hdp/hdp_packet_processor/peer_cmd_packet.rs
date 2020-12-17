use crate::hdp::hdp_server::Ticket;
use crate::hdp::peer::peer_layer::{HypernodeConnectionType, PeerConnectionType, PeerResponse, PeerSignal};

use super::includes::*;
use crate::hdp::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use crate::hdp::peer::peer_crypt::{KEP_STAGE1, KeyExchangeProcess, PeerSessionCrypto};
use hyxe_crypt::toolset::Toolset;
use crate::constants::DEFAULT_PQC_ALGORITHM;
use crate::macros::SessionBorrow;
use std::str::FromStr;
use crate::hdp::hdp_packet_processor::preconnect_packet::calculate_sync_time;
use crate::hdp::peer::p2p_conn_handler::attempt_tcp_simultaneous_hole_punch;
use crate::hdp::hdp_packet_processor::primary_group_packet::get_proper_pqc_and_drill;

#[allow(unused_results)]
/// Insofar, there is no use of endpoint-to-endpoint encryption for PEER_CMD packets because they are mediated between the
/// HyperLAN client and the HyperLAN Server
pub fn process(session_orig: &HdpSession, aux_cmd: u8, packet: HdpPacket, header_drill_version: u32, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    // ALL PEER_CMD packets require that the current session contain a CNAC
    let mut session = inner_mut!(session_orig);
    // Some PEER_CMD packets get encrypted using the endpoint crypto
    let cnac = session.cnac.as_ref()?;
    let pqc = session.post_quantum.as_ref()?;
    log::info!("RECV PEER CMD packet (proxy: {})", proxy_cid_info.is_some());
    let mut state_container = inner_mut!(session.state_container);
    let (pqc, drill) = get_proper_pqc_and_drill(header_drill_version, cnac, pqc, &wrap_inner_mut!(state_container), proxy_cid_info)?;

    let (header, payload, peer_addr, _) = packet.decompose();
    let (header, payload) = validation::aead::validate_custom(&drill, &pqc, &header, payload)?;
    log::info!("PEER CMD packet authenticated");

    match aux_cmd {
        packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST => {
            super::peer::group_broadcast::process(&wrap_inner!(session), header, &payload[..], &pqc, drill)
        }

        packet_flags::cmd::aux::peer_cmd::SIGNAL => {
            let signal = PeerSignal::deserialize_from_bytes(payload)?;
            let timestamp = session.time_tracker.get_global_time_ns();
            let ticket = header.context_info.get().into();

            if !session.is_server {
                // forward the signal to the kernel, with some exceptions.
                match &signal {
                    PeerSignal::Disconnect(vconn, resp) => {
                        let target = resp.as_ref().map(|_| vconn.get_original_implicated_cid()).unwrap_or(vconn.get_original_target_cid());
                        if let None = state_container.active_virtual_connections.remove(&target) {
                            log::error!("Unable to clear vconn");
                        }
                        
                        session.send_to_kernel(HdpServerResult::PeerEvent(signal, ticket))?;
                        return PrimaryProcessorResult::Void;
                    }

                    PeerSignal::PostConnect(conn,_, resp) => {
                        if let Some(resp) = resp {
                            // the connection was mutually accepted. Now, we must begin the KEM subroutine
                            match resp {
                                // the accept case
                                PeerResponse::Accept(_) => {
                                    match conn {
                                        PeerConnectionType::HyperLANPeerToHyperLANPeer(original_implicated_cid, original_target_cid) => {
                                            // this implies this node is receiving an accept_request. As such, we need to NOT
                                            // forward the signal quite yet, and instead, begin the key-exchange process in order to
                                            // establish a working [PeerChannel] system that has a custom post-quantum key and toolset
                                            // unique to the session.
                                            //let mut state_container = inner_mut!(session.state_container);
                                            let mut peer_kem_state_container = PeerKemStateContainer::default();
                                            let alice_pqc = PostQuantumContainer::new_alice(Some(DEFAULT_PQC_ALGORITHM));
                                            let alice_pub_key = alice_pqc.get_public_key();
                                            //log::info!("0. Len: {}, {:?}", alice_pub_key.len(), &alice_pub_key[..10]);
                                            let msg_bytes = Vec::from(alice_pub_key);
                                            peer_kem_state_container.last_state = KEP_STAGE1;
                                            peer_kem_state_container.pqc = Some(alice_pqc);
                                            state_container.peer_kem_states.insert(*original_implicated_cid, peer_kem_state_container);
                                            // finally, prepare the signal and send outbound
                                            // signal: PeerSignal, pqc: &Rc<PostQuantumContainer>, drill: &Drill, ticket: Ticket, timestamp: i64
                                            let signal = PeerSignal::Kem(PeerConnectionType::HyperLANPeerToHyperLANPeer(*original_target_cid, *original_implicated_cid), KeyExchangeProcess::Stage0(msg_bytes));
                                            std::mem::drop(state_container);

                                            // use the pqc of the session to keep the data protected from here to the central
                                            // server and to the endpoint
                                            let pqc = session.post_quantum.as_ref()?;
                                            let ref drill = session.cnac.as_ref()?.get_drill(None)?;

                                            let stage0_peer_kem = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, drill, signal, ticket, timestamp);
                                            log::info!("Sent peer KEM stage 0 outbound");
                                            // send to central server
                                            return PrimaryProcessorResult::ReplyToSender(stage0_peer_kem);
                                        }

                                        _ => unimplemented!("HyperWAN Functionality not yet enabled")
                                    }
                                }

                                _ => {}
                            }
                        }
                    }

                    PeerSignal::Kem(conn, kep) => {
                        return match kep {
                            KeyExchangeProcess::Stage0(alice_public_key) => {
                                log::info!("RECV STAGE 0 PEER KEM");
                                // We generate bob's pqc, as well as a nonce
                                //let mut state_container = inner_mut!(session.state_container);
                                let alice_public_key = &alice_public_key[..];

                                let bob_pqc = PostQuantumContainer::new_bob(DEFAULT_PQC_ALGORITHM, alice_public_key)
                                    .map_err(|err|  {
                                        log::error!("Unable to process bob's PQC: {}", err.to_string());
                                        err
                                    }).ok()?;


                                let bob_ciphertext = Vec::from(bob_pqc.get_ciphertext().ok()?);
                                // now, generate a nonce. Since we are communicating over [PeerSignal], the data is all encrypted
                                let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
                                ThreadRng::default().fill_bytes(&mut nonce);
                                // store the toolset + pqc inside the state container's vconn for later use
                                let nonce_transfer = Vec::from(&nonce as &[u8]);
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage1(bob_ciphertext, nonce_transfer, None));

                                let mut state_container_kem = PeerKemStateContainer::default();
                                state_container_kem.pqc = Some(bob_pqc);
                                state_container_kem.nonce = Some(nonce);
                                state_container_kem.last_state = KEP_STAGE1;
                                state_container.peer_kem_states.insert(conn.get_original_implicated_cid(), state_container_kem);
                                // send signal
                                std::mem::drop(state_container);
                                let pqc = session.post_quantum.as_ref()?;

                                let latest_drill = session.cnac.as_ref()?.get_drill(None)?;

                                let stage1_kem = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, &latest_drill, signal, ticket, timestamp);
                                log::info!("Sent stage 1 peer KEM");
                                PrimaryProcessorResult::ReplyToSender(stage1_kem)
                            }

                            KeyExchangeProcess::Stage1(bob_ciphertext, nonce, Some(bob_public_addr)) => {
                                // Here, we finalize the creation of the pqc for alice, and then, generate the new toolset
                                // The toolset gets encrypted to ensure the central server doesn't see the toolset. This is
                                // to combat a "chinese communist hijack" scenario wherein a rogue government takes over our
                                // central servers
                                log::info!("RECV STAGE 1 PEER KEM");
                                let security_level = session.security_level;
                                //let mut state_container = inner_mut!(session.state_container);
                                let peer_cid = conn.get_original_implicated_cid();
                                let this_cid = conn.get_original_target_cid();
                                let mut kem_state = state_container.peer_kem_states.remove(&peer_cid)?;
                                let mut pqc = kem_state.pqc.take()?; // TODO: put in active virtual conn
                                pqc.alice_on_receive_ciphertext(&bob_ciphertext[..]).ok()?;
                                // now, create a new toolset and encrypt it
                                // NOTE: when this toolset gets transmitted, it retains this_cid
                                // As such, the other end MUST change the CID internally for BOTH
                                // toolset AND the single drill
                                let mut toolset = Toolset::new(this_cid).ok()?;
                                let toolset_bytes = toolset.serialize_to_vec().ok()?;
                                let encrypted_toolset = pqc.encrypt(toolset_bytes.as_slice(), &nonce[..]).ok()?;
                                // now, register the loaded PQC + toolset into the virtual conn
                                let peer_crypto = PeerSessionCrypto::new(pqc, toolset);
                                let vconn_type = VirtualConnectionType::HyperLANPeerToHyperLANPeer(this_cid, peer_cid);
                                let bob_socket_addr = SocketAddr::from_str(bob_public_addr.as_str()).ok()?;
                                log::info!("[STUN] Peer public addr: {:?}", &bob_socket_addr);
                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(bob_socket_addr, security_level, ticket, peer_cid, vconn_type, peer_crypto);
                                // dont send the channel until the other end creates it. When the other end gets it, it will send an ACK.
                                // Even if they send data while the ACK is in transit, the channel's receiver will get enqueued
                                kem_state.channel = Some(channel);
                                state_container.peer_kem_states.insert(peer_cid, kem_state);
                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);

                                // now that the virtual connection is created on this end, we need to do the same to the other end
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage2(encrypted_toolset, None));
                                std::mem::drop(state_container);
                                // we need to use the session pqc since this signal needs to get processed by the center node
                                let pqc = session.post_quantum.as_ref()?;
                                let latest_drill = session.cnac.as_ref()?.get_drill(None)?;
                                let stage2_kem_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, &latest_drill, signal, ticket, timestamp);
                                log::info!("Sent stage 2 peer KEM");
                                PrimaryProcessorResult::ReplyToSender(stage2_kem_packet)
                            }

                            KeyExchangeProcess::Stage2(encrypted_toolset, Some(alice_public_addr)) => {
                                // In order to get the toolset's bytes, we need to decrypt it using the pqc we have stored in our state container
                                log::info!("RECV STAGE 2 PEER KEM");
                                let peer_cid = conn.get_original_implicated_cid();
                                let this_cid = conn.get_original_target_cid();
                                let security_level = session.security_level;
                                //let mut state_container = inner_mut!(session.state_container);
                                let mut kem = state_container.peer_kem_states.get_mut(&peer_cid)?;
                                kem.local_is_initiator = true;
                                // take the pqc
                                let bob_pqc = kem.pqc.take()?;
                                let nonce = kem.nonce.take()?;
                                let decrypted_toolset = bob_pqc.decrypt(&encrypted_toolset[..], &nonce).ok()?;
                                let toolset = Toolset::deserialize_from_bytes(decrypted_toolset.as_slice()).ok()?;
                                debug_assert_eq!(toolset.cid, peer_cid);
                                let toolset = toolset.force_update_cid_init_only(this_cid);
                                debug_assert_eq!(toolset.cid, this_cid);
                                // since the AES-GCM was a success, we can now entrust that the toolset is perfectly symmetric to the
                                // other side's toolset
                                let peer_crypto = PeerSessionCrypto::new(bob_pqc, toolset);
                                let (endpoint_pqc, endpoint_drill) = peer_crypto.get_pqc_and_drill(None)?;
                                // create an endpoint vconn
                                let vconn_type = VirtualConnectionType::HyperLANPeerToHyperLANPeer(this_cid, peer_cid);
                                let alice_socket_addr = SocketAddr::from_str(alice_public_addr.as_str()).ok()?;
                                log::info!("[STUN] Peer public addr: {:?}", &alice_socket_addr);
                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(alice_socket_addr, security_level, ticket, peer_cid, vconn_type, peer_crypto);

                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);
                                // send ack. But first, send the channel to the kernel to the kernel
                                state_container.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel)).ok()?;
                                let header_time = header.timestamp.get();
                                let (sync_instant, sync_time_ns) = calculate_sync_time(timestamp, header_time);
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage3(sync_time_ns));

                                std::mem::drop(state_container);

                                let pqc = session.post_quantum.as_ref()?;
                                let ref latest_drill = session.cnac.as_ref()?.get_drill(None)?;
                                let stage3_kem_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, latest_drill, signal, ticket, timestamp);
                                log::info!("Sent stage 3 peer KEM");
                                // now, start the task
                                // session: HdpSession, expected_peer_cid: u64, peer_endpoint_addr: SocketAddr, implicated_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, sync_time: Instant
                                let implicated_cid = session.implicated_cid.clone();
                                let kernel_tx = session.kernel_tx.clone();
                                let hole_punch_future = attempt_tcp_simultaneous_hole_punch(conn.reverse(), ticket,session_orig.clone(),alice_socket_addr, implicated_cid, kernel_tx, sync_instant, endpoint_pqc, endpoint_drill);
                                let _ = spawn!(hole_punch_future);
                                PrimaryProcessorResult::ReplyToSender(stage3_kem_packet)
                            }

                            KeyExchangeProcess::Stage3(sync_time_ns) => {
                                // get the channel out, and send it to the kernel
                                log::info!("RECV STAGE 3 PEER KEM (sync time: {}ns)", sync_time_ns);
                                let peer_cid = conn.get_original_implicated_cid();
                                let diff = Duration::from_nanos(i64::abs(timestamp - sync_time_ns) as u64);
                                let sync_instant = Instant::now() + diff;
                                let implicated_cid = session.implicated_cid.clone();
                                let kernel_tx = session.kernel_tx.clone();

                                //let mut state_container = inner_mut!(session.state_container);
                                let endpoint_container = state_container.active_virtual_connections.get(&peer_cid)?.endpoint_container.as_ref()?;
                                let peer_socket_addr = endpoint_container.peer_socket_addr;
                                let (endpoint_pqc, endpoint_drill) = endpoint_container.endpoint_crypto.get_pqc_and_drill(None)?;
                                let kem_state_container = state_container.peer_kem_states.get_mut(&conn.get_original_implicated_cid())?;
                                let channel = kem_state_container.channel.take()?;
                                kem_state_container.local_is_initiator = false;
                                let hole_punch_future = attempt_tcp_simultaneous_hole_punch(conn.reverse(), ticket, session_orig.clone(), peer_socket_addr, implicated_cid, kernel_tx, sync_instant, endpoint_pqc, endpoint_drill);
                                let _ = spawn!(hole_punch_future);

                                state_container.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel)).ok()?;
                                PrimaryProcessorResult::Void
                            }

                            KeyExchangeProcess::HolePunchEstablished => {
                                log::info!("RECV HolePunchEstablished packet");
                                // The other side is telling us it made a connection. It still is waiting on this node to verify
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
                                    if state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                        log::info!("Successfully upgraded direct p2p connection for {}@{:?}", peer_cid, peer_addr);
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
                                let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal_endpoint(&pqc, &drill, signal, ticket, timestamp, peer_cid);
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
                                    if state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                        log::info!("Successfully upgraded direct p2p connection for {}@{:?}. Process complete!", peer_cid, peer_addr);
                                        // Great. Now, tell the other end to upgrade their connection
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
                                        return PrimaryProcessorResult::EndSession("Other connection established. Will drop this exact connection")
                                    } else {
                                        // since this connection works, but the other connection has not been established, we need to wait for it
                                        // to send this node a HolePunchEstablished. This stream will get dropped if a
                                        // HolePunchEstablished arrives (since the other stream belongs to the initiator, and this one does not).
                                        // During the upgrade process, since this stream would get overwritten if the initiator stream goes-in,
                                        // we will upgrade the connection for now
                                        kem_state_container.verified_socket_addr = Some(peer_addr);
                                        log::info!("Connection established, but is a non-initiator stream. Will upgrade, but may be overwritten in the interim");
                                        if state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                            log::info!("Successfully upgraded direct p2p connection for {}@{:?}. May be overwritten though ...", peer_cid, peer_addr);
                                            // Great. Now, tell the other end to upgrade their connection
                                        } else {
                                            log::warn!("Unable to upgrade direct P2P connection for {:?}. Missing items? (provisional)", peer_addr);
                                        }
                                    }
                                }

                                PrimaryProcessorResult::Void
                            }

                            KeyExchangeProcess::HolePunchFailed => {
                                log::info!("RECV HolePunchFailed");
                                // the other side's TCP connection attempt failed. This side's, if up, is already up by itself
                                // as such,
                                /*
                                let peer_cid = conn.get_original_implicated_cid();
                                let kem_state_container = state_container.peer_kem_states.get(&peer_cid)?;
                                let possible_verified_conn = kem_state_container.verified_socket_addr.clone();
                                // since the HolePunchFailed packet comes
                                if state_container.upgrade_provisional_direct_p2p_connection(peer_addr, peer_cid, possible_verified_conn) {
                                    log::info!("Successfully upgraded direct p2p connection for {}@{:?}. Process complete!", peer_cid, peer_addr);
                                    // Great. Now, tell the other end to upgrade their connection
                                }*/

                                PrimaryProcessorResult::Void
                            }

                            _ => {
                                log::error!("INVALID KEM signal");
                                PrimaryProcessorResult::Void
                            }
                        }
                    }

                    _ => {}
                }

                log::info!("Forwarding PEER signal to kernel ...");
                session.kernel_tx.unbounded_send(HdpServerResult::PeerEvent(signal, ticket))?;
                PrimaryProcessorResult::Void
            } else {
                std::mem::drop(state_container);
                process_signal_command_as_server(signal, ticket, wrap_inner_mut!(session), drill, header, timestamp)
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

#[inline]
fn process_signal_command_as_server<K: ExpectedInnerTargetMut<HdpSessionInner>>(signal: PeerSignal, ticket: Ticket, session: InnerParameterMut<K, HdpSessionInner>, drill: Drill, _header: LayoutVerified<&[u8], HdpHeader>, timestamp: i64) -> PrimaryProcessorResult {
    match signal {
        PeerSignal::Kem(conn, mut kep) => {
            // before just routing the signals, we also need to add socket information into intercepted stage1 and stage2 signals
            // to allow for STUN-like NAT traversal
            // this gives peer A the socket of peer B and vice versa
            let socket_addr = session.remote_peer.to_string();
            match &mut kep {
                KeyExchangeProcess::Stage1(_, _, val) | KeyExchangeProcess::Stage2(_, val)=> {
                    *val = Some(socket_addr);
                }

                 _ => {}
            }

            // since this is the server, we just need to route this to the target_cid
            let sess_mgr = inner!(session.session_manager);
            let signal_to = PeerSignal::Kem(conn, kep);
            let res = sess_mgr.send_signal_to_peer_direct(conn.get_original_target_cid(),move |peer_pqc, peer_drill| {
                hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_pqc, peer_drill, signal_to, ticket, timestamp)
            });

            if let Err(err) = res {
                let pqc = session.post_quantum.as_ref()?;
                let ref drill = session.cnac.as_ref()?.get_drill(None)?;
                reply_to_sender_err(err, pqc, drill, ticket, timestamp)
            } else {
                PrimaryProcessorResult::Void
            }
        }

        PeerSignal::PostRegister(peer_conn_type, username, _ticket_opt, peer_response) => {
            // check to see if the client is connected, and if not, send to HypernodePeerLayer
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    const TIMEOUT: Duration = Duration::from_secs(60*60); // 1 hour
                    // if the peer response is some, then HyperLAN Client B responded
                    if let Some(peer_response) = peer_response {
                        // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                        route_signal_response(PeerSignal::PostRegister(peer_conn_type, username.clone(), Some(ticket), Some(peer_response)), implicated_cid, target_cid, timestamp, ticket, session, &drill,
                        |this_sess, peer_sess, _original_tracked_posting| {
                            if let Some(this_cnac) = this_sess.cnac.as_ref() {
                                if let Some(other_cnac) = peer_sess.cnac.as_ref() {
                                    this_cnac.register_hyperlan_p2p_as_server(other_cnac);
                                    log::info!("Observed registration between {} <-> {} locally", implicated_cid, target_cid);
                                }
                            }
                        })
                    } else {
                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase)
                        route_signal_and_register_ticket_forwards(PeerSignal::PostRegister(peer_conn_type, username, Some(ticket), None), TIMEOUT, implicated_cid, target_cid, timestamp, ticket, session, drill)
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    unimplemented!("HyperWAN functionality not implemented")
                }
            }
        }

        PeerSignal::Deregister(peer_conn_type) => {
            // in deregistration, we send a Deregister signal to the peer (if connected)
            // then, delete the cid entry from the CNAC and save to the local FS
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let cnac = session.cnac.as_ref()?;
                    let pqc = session.post_quantum.as_ref()?;
                    if cnac.get_id() == implicated_cid {
                        let ref drill = cnac.get_drill(None)?;
                        match cnac.remove_hyperlan_peer(target_cid) {
                            Some(_removed_mutual_peer) => {
                                // route the original signal to the other end. If not connected, don't bother
                                if session.session_manager.session_active(target_cid) {
                                    let peer_alert_signal = signal.clone();
                                    if !session.session_manager.send_signal_to_peer(target_cid, ticket, peer_alert_signal, timestamp) {
                                        log::warn!("Unable to send packet to {}", target_cid);
                                    }
                                }

                                // now, send a success packet to the client
                                let success_cmd = PeerSignal::SignalReceived(ticket);
                                let rebound_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, drill, success_cmd, ticket, timestamp);
                                PrimaryProcessorResult::ReplyToSender(rebound_packet)
                            }

                            None => {
                                // unable to find the peer
                                let error_signal = PeerSignal::SignalError(ticket, format!("Target peer {} is not registered as a mutual with {}", target_cid, implicated_cid));
                                let error_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, drill, error_signal, ticket, timestamp);
                                PrimaryProcessorResult::ReplyToSender(error_packet)
                            }
                        }
                    } else {
                        PrimaryProcessorResult::Void
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    unimplemented!("HyperWAN functionality not yet enabled")
                }
            }
        }

        PeerSignal::PostConnect(peer_conn_type, _ticket_opt, peer_response) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    const TIMEOUT: Duration = Duration::from_secs(60*60);
                    if let Some(peer_response) = peer_response {
                        // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                        route_signal_response(PeerSignal::PostConnect(peer_conn_type, Some(ticket), Some(peer_response)), implicated_cid, target_cid, timestamp, ticket, session, &drill,
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
                                        let this_udp_sender = this_sess_state_container.udp_sender.clone();
                                        let peer_udp_sender = peer_sess_state_container.udp_sender.clone();
                                        // rel to this local sess, the key = target_cid, then (implicated_cid, target_cid)
                                        let virtual_conn_relative_to_this = VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid);
                                        let virtual_conn_relative_to_peer = VirtualConnectionType::HyperLANPeerToHyperLANPeer(target_cid, implicated_cid);
                                        this_sess_state_container.insert_new_virtual_connection(target_cid, virtual_conn_relative_to_this, peer_udp_sender, peer_tcp_sender);
                                        peer_sess_state_container.insert_new_virtual_connection(implicated_cid, virtual_conn_relative_to_peer, this_udp_sender, this_tcp_sender);
                                        log::info!("Virtual connection between {} <-> {} forged", implicated_cid, target_cid);
                                        // TODO: Ensure that, upon disconnect, the the corresponding entry gets dropped in the connection table of not the dropped peer

                                    }
                                }
                        })
                    } else {
                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase)
                        route_signal_and_register_ticket_forwards(PeerSignal::PostConnect(peer_conn_type, Some(ticket), None), TIMEOUT, implicated_cid, target_cid, timestamp, ticket, session, drill)
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    unimplemented!("HyperWAN functionality not implemented")
                }
            }
        }

        PeerSignal::Disconnect(peer_conn_type, resp) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let pqc = session.post_quantum.as_ref()?;
                    let mut state_container = inner_mut!(session.state_container);
                    if let Some(_removed_conn) = state_container.active_virtual_connections.remove(&target_cid) {
                        // now, try removing the connection from the other peer
                        std::mem::drop(state_container);
                        let resp = Some(resp.unwrap_or(PeerResponse::Disconnected(format!("Peer {} closed the virtual connection to {}", implicated_cid, target_cid))));
                        let signal_to_peer = PeerSignal::Disconnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid), resp);
                        // now, remove target CID's v_conn to `implicated_cid`
                        let res = session.session_manager.disconnect_virtual_conn(implicated_cid, target_cid, move |peer_pqc, peer_latest_drill| {
                            // send signal to peer
                            hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_pqc, peer_latest_drill, signal_to_peer, ticket, timestamp)
                        });

                        // now, send a packet back to the source
                        res.map_or_else(|err| reply_to_sender_err(err, pqc, &drill, ticket, timestamp),
                                        |_| reply_to_sender(PeerSignal::Disconnect(peer_conn_type, None), pqc, &drill, ticket, timestamp))
                    } else {
                        reply_to_sender_err(format!("{} is not connected to {}", implicated_cid, target_cid), pqc, &drill, ticket, timestamp)
                    }
                }

                _ => {
                    unimplemented!("HyperWAN functionality not implemented")
                }
            }
        }

        PeerSignal::GetRegisteredPeers(hypernode_conn_type, _resp_opt) => {
            match hypernode_conn_type {
                HypernodeConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                    let pqc = session.post_quantum.as_ref()?;
                    let rebound_signal = if let Some(registered_local_clients) = session.account_manager.get_registered_impersonal_cids() {
                        let online_status = session.session_manager.check_online_status(&registered_local_clients);
                        PeerSignal::GetRegisteredPeers(hypernode_conn_type, Some(PeerResponse::RegisteredCids(registered_local_clients, online_status)))
                    } else {
                        PeerSignal::GetRegisteredPeers(hypernode_conn_type, None)
                    };

                    reply_to_sender(rebound_signal, pqc, &drill, ticket, timestamp)
                }

                HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    unimplemented!("HyperWAN functionality not implemented")
                }
            }
        }

        PeerSignal::GetMutuals(hypernode_conn_type, _resp_opt) => {
            match hypernode_conn_type {
                HypernodeConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                    let pqc = session.post_quantum.as_ref()?;
                    let rebound_signal = if let Some(mutuals) = session.cnac.as_ref()?.get_hyperlan_peer_list() {
                        let online_status = session.session_manager.check_online_status(&mutuals);
                        PeerSignal::GetMutuals(hypernode_conn_type, Some(PeerResponse::RegisteredCids(mutuals, online_status)))
                    } else {
                        PeerSignal::GetMutuals(hypernode_conn_type, None)
                    };

                    reply_to_sender(rebound_signal, pqc, &drill, ticket, timestamp)
                }

                HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    unimplemented!("HyperWAN functionality not implemented")
                }
            }
        }

        PeerSignal::BroadcastConnected(_hypernode_conn_type) => {
            unimplemented!()
        }

        PeerSignal::PostFileUploadRequest(_peer_conn_type, _file_metadata, _ticket) => {
            unimplemented!()
        }

        PeerSignal::AcceptFileUploadRequest(_peer_conn_type, _ticket) => {
            unimplemented!()
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
    }
}

#[inline]
/// This just makes the repeated operation above cleaner. By itself does not send anything; must return the result of this closure directly
fn reply_to_sender(signal: PeerSignal, pqc: &PostQuantumContainer, drill: &Drill, ticket: Ticket, timestamp: i64) -> PrimaryProcessorResult {
    let packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, drill, signal, ticket, timestamp);
    PrimaryProcessorResult::ReplyToSender(packet)
}

#[inline]
fn reply_to_sender_err<E: ToString>(err: E, pqc: &PostQuantumContainer, drill: &Drill, ticket: Ticket, timestamp: i64) -> PrimaryProcessorResult {
    let err_signal = PeerSignal::SignalError(ticket, err.to_string());
    let err_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, drill, err_signal, ticket, timestamp);
    PrimaryProcessorResult::ReplyToSender(err_packet)
}

fn route_signal_and_register_ticket_forwards<K: ExpectedInnerTargetMut<HdpSessionInner>>(signal: PeerSignal, timeout: Duration, implicated_cid: u64, target_cid: u64, timestamp: i64, ticket: Ticket, session: InnerParameterMut<K, HdpSessionInner>, drill: Drill) -> PrimaryProcessorResult {
    // We use the same logic as the register post
    let to_primary_stream = session.to_primary_stream.clone()?;
    let pqc = session.post_quantum.as_ref()?;
    let mut sess_mgr = inner_mut!(session.session_manager);
    let pqc2 = pqc.clone();
    let drill2 = drill.clone();
    // Give the target_cid 10 seconds to respond
    let res = sess_mgr.route_signal_primary(implicated_cid, target_cid, ticket, signal.clone(), move |peer_pqc, peer_drill| {
        hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_pqc, peer_drill, signal.clone(), ticket, timestamp)
    }, timeout, move |stale_signal| {
        // on timeout, run this
        log::warn!("Running timeout closure. Sending error message to {}", implicated_cid);
        let error_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(&pqc2, &drill2, stale_signal, ticket, timestamp);
        let _ = to_primary_stream.unbounded_send(error_packet);
    });

    // Then, we tell the implicated_cid's node that we have handled the message. However, the peer has yet to respond
    if let Err(err) = res {
        reply_to_sender_err(err, &pqc, &drill, ticket, timestamp)
    } else {
        let received_signal = PeerSignal::SignalReceived(ticket);
        reply_to_sender(received_signal, &pqc, &drill, ticket, timestamp)
    }
}

// returns (true, status) if the process was a success, or (false, success) otherwise
fn route_signal_response<K: ExpectedInnerTargetMut<HdpSessionInner>>(signal: PeerSignal, implicated_cid: u64, target_cid: u64, timestamp: i64, ticket: Ticket, session: InnerParameterMut<K, HdpSessionInner>, drill: &Drill, on_route_finished: impl FnOnce(InnerParameterMut<K, HdpSessionInner>, InnerParameterMut<SessionBorrow, HdpSessionInner>, PeerSignal)) -> PrimaryProcessorResult {
    let pqc = session.post_quantum.as_ref()?;
    let mut sess_mgr = inner_mut!(session.session_manager);
    log::info!("impl: {} | target: {}", implicated_cid, target_cid);

    let res = sess_mgr.route_signal_response_primary(implicated_cid, target_cid, ticket, move |peer_pqc, peer_latest_drill| {
        hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_pqc, peer_latest_drill, signal, ticket, timestamp)
    });
    std::mem::drop(sess_mgr);

    match res {
        Ok((peer_sess, original_posting)) => {
            // send a notification that the server forwarded the signal
            let received_signal = PeerSignal::SignalReceived(ticket);
            let ret = reply_to_sender(received_signal, &pqc, drill, ticket, timestamp);
            log::info!("Running on_route_finished subroutine");
            let mut peer_sess_ref = inner_mut!(peer_sess);
            on_route_finished(session, InnerParameterMut::from(&mut peer_sess_ref), original_posting);
            ret
        }

        Err(err) => {
            reply_to_sender_err(err, &pqc, drill, ticket, timestamp)
        }
    }

}