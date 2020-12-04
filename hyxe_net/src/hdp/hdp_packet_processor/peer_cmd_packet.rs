use std::str::FromStr;

use hyxe_crypt::toolset::Toolset;

use crate::constants::DEFAULT_PQC_ALGORITHM;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::peer::peer_crypt::{KEP_STAGE1, KeyExchangeProcess, PeerSessionCrypto};
use crate::hdp::peer::peer_layer::{HypernodeConnectionType, PeerConnectionType, PeerResponse, PeerSignal};
use crate::hdp::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use crate::macros::SessionBorrow;

use super::includes::*;

#[allow(unused_results)]
/// Insofar, there is no use of endpoint-to-endpoint encryption for PEER_CMD packets because they are mediated between the
/// HyperLAN client and the HyperLAN Server
pub fn process(session: &HdpSession, aux_cmd: u8, packet: HdpPacket) -> PrimaryProcessorResult {
    // ALL PEER_CMD packets require that the current session contain a CNAC
    let mut session = inner_mut!(session);
    let cnac = session.cnac.as_ref()?;
    let pqc = session.post_quantum.as_ref()?;
    log::info!("RECV PEER CMD packet");
    let (header, payload, _, _) = packet.decompose();
    let (header, payload, drill) = validation::peer_cmd::validate(cnac, &pqc, &header, payload)?;
    log::info!("PEER CMD packet authenticated");

    match aux_cmd {
        packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST => {
            super::peer::group_broadcast::process(&wrap_inner!(session), header, &payload[..], pqc, drill)
        }

        packet_flags::cmd::aux::peer_cmd::SIGNAL => {
            let signal = PeerSignal::deserialize_from_bytes(payload)?;
            let timestamp = session.time_tracker.get_global_time_ns();
            let ticket = header.context_info.get().into();

            if !session.is_server {
                // forward the signal to the kernel, with some exceptions.
                match &signal {
                    // the connection was mutually accepted. Now, we must begin the KEM subroutine
                    PeerSignal::PostConnect(conn,_, resp) => {
                        if let Some(resp) = resp {
                            match resp {
                                // the accept
                                PeerResponse::Accept(_) => {
                                    match conn {
                                        PeerConnectionType::HyperLANPeerToHyperLANPeer(original_implicated_cid, original_target_cid) => {
                                            // this implies this node is receiving an accept_request. As such, we need to NOT
                                            // forward the signal quite yet, and instead, begin the key-exchange process in order to
                                            // establish a working [PeerChannel] system that has a custom post-quantum key and toolset
                                            // unique to the session.
                                            let mut state_container = inner_mut!(session.state_container);
                                            let mut peer_kem_state_container = PeerKemStateContainer::default();
                                            let alice_pqc = PostQuantumContainer::new_alice(Some(DEFAULT_PQC_ALGORITHM));
                                            let alice_pub_key = alice_pqc.get_public_key();
                                            log::info!("0. Len: {}, {:?}", alice_pub_key.len(), &alice_pub_key[..10]);
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
                                let mut state_container = inner_mut!(session.state_container);
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
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage1(bob_ciphertext, nonce_transfer));

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

                            KeyExchangeProcess::Stage1(bob_ciphertext, nonce) => {
                                // Here, we finalize the creation of the pqc for alice, and then, generate the new toolset
                                // The toolset gets encrypted to ensure the central server doesn't see the toolset. This is
                                // to combat a "chinese communist hijack" scenario wherein a rogue government takes over our
                                // central servers
                                log::info!("RECV STAGE 1 PEER KEM");
                                let security_level = session.security_level;
                                let mut state_container = inner_mut!(session.state_container);
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
                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(security_level, ticket, peer_cid, vconn_type, peer_crypto);
                                // dont send the channel until the other end creates it. When the other end gets it, it will send an ACK.
                                // Even if they send data while the ACK is in transit, the channel's receiver will get enqueued
                                kem_state.channel = Some(channel);
                                state_container.peer_kem_states.insert(peer_cid, kem_state);
                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);

                                // now that the virtual connection is created on this end, we need to do the same to the other end
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage2(encrypted_toolset));
                                std::mem::drop(state_container);
                                let pqc = session.post_quantum.as_ref()?;
                                let latest_drill = session.cnac.as_ref()?.get_drill(None)?;
                                let stage2_kem_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, &latest_drill, signal, ticket, timestamp);
                                log::info!("Sent stage 2 peer KEM");
                                PrimaryProcessorResult::ReplyToSender(stage2_kem_packet)
                            }

                            KeyExchangeProcess::Stage2(encrypted_toolset) => {
                                // In order to get the toolset's bytes, we need to decrypt it using the pqc we have stored in our state container
                                log::info!("RECV STAGE 2 PEER KEM");
                                let peer_cid = conn.get_original_implicated_cid();
                                let this_cid = conn.get_original_target_cid();
                                let security_level = session.security_level;
                                let mut state_container = inner_mut!(session.state_container);
                                let mut kem = state_container.peer_kem_states.remove(&peer_cid)?;
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
                                // create an endpoint vconn
                                let vconn_type = VirtualConnectionType::HyperLANPeerToHyperLANPeer(this_cid, peer_cid);
                                let channel = state_container.insert_new_peer_virtual_connection_as_endpoint(security_level, ticket, peer_cid, vconn_type, peer_crypto);

                                log::info!("Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);
                                // send ack. But first, send the channel to the kernel to the kernel
                                state_container.kernel_tx.send(HdpServerResult::PeerChannelCreated(ticket, channel)).ok()?;
                                let signal = PeerSignal::Kem(conn.reverse(), KeyExchangeProcess::Stage3);
                                std::mem::drop(state_container);

                                let pqc = session.post_quantum.as_ref()?;
                                let ref latest_drill = session.cnac.as_ref()?.get_drill(None)?;
                                let stage3_kem_packet = hdp_packet_crafter::peer_cmd::craft_peer_signal(pqc, latest_drill, signal, ticket, timestamp);
                                log::info!("Sent stage 3 peer KEM");
                                PrimaryProcessorResult::ReplyToSender(stage3_kem_packet)
                            }

                            KeyExchangeProcess::Stage3 => {
                                // get the channel out, and send it to the kernel
                                log::info!("RECV STAGE 3 PEER KEM");
                                let mut state_container = inner_mut!(session.state_container);
                                let kem_state_container = state_container.peer_kem_states.remove(&conn.get_original_implicated_cid())?;
                                let channel = kem_state_container.channel?;
                                state_container.kernel_tx.send(HdpServerResult::PeerChannelCreated(ticket, channel)).ok()?;
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
                session.kernel_tx.send(HdpServerResult::PeerEvent(signal, ticket))?;
                PrimaryProcessorResult::Void
            } else {
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
        PeerSignal::Kem(conn, kep) => {
            // since this is the server, we just need to route this to the target_cid
            let sess_mgr = inner!(session.session_manager);
            let signal_to = PeerSignal::Kem(conn, kep);
            let res = sess_mgr.send_signal_to_peer_direct(conn.get_original_target_cid(), move |peer_pqc, peer_drill| {
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
                    let rebound_signal = if let Some(registered_local_clients) = session.account_manager.get_registered_hyperlan_cids() {
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
            session.kernel_tx.send(HdpServerResult::PeerEvent(PeerSignal::SignalError(ticket, err), ticket))?;
            PrimaryProcessorResult::Void
        }

        PeerSignal::SignalReceived(ticket) => {
            session.kernel_tx.send(HdpServerResult::PeerEvent(signal, ticket))?;
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
        let _ = to_primary_stream.send(error_packet);
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