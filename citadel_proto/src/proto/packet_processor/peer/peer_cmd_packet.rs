use std::sync::atomic::Ordering;

use bytes::BytesMut;

use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::prelude::ConstructorOpts;
use citadel_crypt::stacked_ratchet::constructor::{
    AliceToBobTransfer, BobToAliceTransfer, BobToAliceTransferType, StackedRatchetConstructor,
};
use citadel_crypt::stacked_ratchet::StackedRatchet;
use citadel_crypt::toolset::Toolset;
use citadel_user::serialization::SyncIO;
use netbeam::sync::RelativeNodeType;

use crate::error::NetworkError;
use crate::proto::node_result::{PeerChannelCreated, PeerEvent};
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::packet_processor::includes::*;
use crate::proto::packet_processor::peer::group_broadcast;
use crate::proto::packet_processor::preconnect_packet::{
    calculate_sync_time, generate_hole_punch_crypt_container,
};
use crate::proto::packet_processor::primary_group_packet::{
    get_proper_hyper_ratchet, get_resp_target_cid,
};
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::p2p_conn_handler::attempt_simultaneous_hole_punch;
use crate::proto::peer::peer_crypt::{KeyExchangeProcess, PeerNatInfo};
use crate::proto::peer::peer_layer::{
    HyperNodePeerLayerInner, HypernodeConnectionType, PeerConnectionType, PeerResponse, PeerSignal,
    UdpMode,
};
use crate::proto::remote::Ticket;
use crate::proto::session_manager::HdpSessionManager;
use crate::proto::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use netbeam::sync::network_endpoint::NetworkEndpoint;

#[allow(unused_results)]
/// Insofar, there is no use of endpoint-to-endpoint encryption for PEER_CMD packets because they are mediated between the
/// HyperLAN client and the HyperLAN Server
#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "citadel", skip_all, ret, err, fields(is_server = session_orig.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub async fn process_peer_cmd(
    session_orig: &HdpSession,
    aux_cmd: u8,
    packet: HdpPacket,
    header_drill_version: u32,
    endpoint_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    // ALL PEER_CMD packets require that the current session contain a CNAC (not anymore since switching to async)
    let session = session_orig.clone();
    let (header, payload, _peer_addr, _) = packet.decompose();

    let (implicated_cid, sess_hyper_ratchet, payload, security_level) = {
        // Some PEER_CMD packets get encrypted using the endpoint crypto

        log::trace!(target: "citadel", "RECV PEER CMD packet (proxy: {})", endpoint_cid_info.is_some());
        let state_container = inner_state!(session.state_container);
        let implicated_cid = return_if_none!(session.implicated_cid.get());
        let sess_hyper_ratchet = return_if_none!(
            get_proper_hyper_ratchet(header_drill_version, &state_container, endpoint_cid_info),
            "Unable to obtain peer HR (P_CMD_PKT)"
        );

        let (header, payload) = return_if_none!(
            validation::aead::validate_custom(&sess_hyper_ratchet, &header, payload),
            "Unable to validate peer CMD packet"
        );
        let security_level = header.security_level.into();
        log::trace!(target: "citadel", "PEER CMD packet authenticated");
        (implicated_cid, sess_hyper_ratchet, payload, security_level)
    };

    let task = async move {
        let session = &session;
        // we can unwrap below safely since the header layout has already been verified
        let header = LayoutVerified::new(&*header).unwrap() as LayoutVerified<&[u8], HdpHeader>;

        match aux_cmd {
            packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST => {
                group_broadcast::process_group_broadcast(
                    session,
                    header,
                    &payload[..],
                    &sess_hyper_ratchet,
                )
                .await
            }

            packet_flags::cmd::aux::peer_cmd::SIGNAL => {
                let signal = return_if_none!(
                    PeerSignal::deserialize_from_vector(&payload[..]).ok(),
                    "Unable to deser PeerSignal packet"
                );
                let timestamp = session.time_tracker.get_global_time_ns();
                let ticket = header.context_info.get().into();

                if !session.is_server {
                    // forward the signal to the kernel, with some exceptions.
                    match &signal {
                        PeerSignal::Disconnect(vconn, resp) => {
                            // below line is confusing. The logic is answered in the server block for PeerSignal::Disconnect
                            let target = resp
                                .as_ref()
                                .map(|_| vconn.get_original_implicated_cid())
                                .unwrap_or_else(|| vconn.get_original_target_cid());
                            let state_container = inner_state!(session.state_container);
                            if let Some(v_conn) =
                                state_container.active_virtual_connections.get(&target)
                            {
                                v_conn.is_active.store(false, Ordering::SeqCst); //prevent further messages from being sent from this node
                                                                                 // ... but, we still want any messages already sent to be processed

                                let last_packet = v_conn.last_delivered_message_timestamp.clone();
                                let state_container_ref = session.state_container.clone();

                                std::mem::drop(state_container);

                                let task = async move {
                                    loop {
                                        if let Some(ts) = last_packet.load(Ordering::SeqCst) {
                                            if ts.elapsed() > Duration::from_millis(1500)
                                                && inner_mut_state!(state_container_ref)
                                                    .enqueued_packets
                                                    .entry(target)
                                                    .or_default()
                                                    .is_empty()
                                            {
                                                break;
                                            }
                                        } else if inner_mut_state!(state_container_ref)
                                            .enqueued_packets
                                            .entry(target)
                                            .or_default()
                                            .is_empty()
                                        {
                                            break;
                                        }

                                        tokio::time::sleep(Duration::from_millis(1500)).await;
                                    }

                                    log::trace!(target: "citadel", "[Peer Vconn] No packets received in the last 1500ms; will drop the connection cleanly");
                                    // once we're done waiting for packets to stop showing up, we can remove the container to end the underlying TCP stream
                                    let mut state_container = inner_mut_state!(state_container_ref);
                                    let _ =
                                        state_container.active_virtual_connections.remove(&target);
                                };

                                spawn!(task);
                            } else {
                                log::warn!(target: "citadel", "Vconn already removed");
                            }

                            session.send_to_kernel(NodeResult::PeerEvent(PeerEvent {
                                event: signal,
                                ticket,
                            }))?;
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::DisconnectUDP(vconn) => {
                            let target_cid = return_if_none!(get_resp_target_cid(vconn));
                            inner_mut_state!(session.state_container)
                                .remove_udp_channel(target_cid);
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::DeregistrationSuccess(peer_cid) => {
                            log::trace!(target: "citadel", "[Deregistration] about to remove peer {} from {} at the endpoint", peer_cid, implicated_cid);
                            let acc_mgr = &session.account_manager;
                            let kernel_tx = &session.kernel_tx;

                            if (acc_mgr
                                .get_persistence_handler()
                                .deregister_p2p_as_client(implicated_cid, *peer_cid)
                                .await?)
                                .is_none()
                            {
                                log::warn!(target: "citadel", "Unable to remove hyperlan peer {}", peer_cid);
                            }

                            kernel_tx.unbounded_send(NodeResult::PeerEvent(PeerEvent {
                                event: PeerSignal::DeregistrationSuccess(*peer_cid),
                                ticket,
                            }))?;
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::PostRegister(
                            vconn,
                            _peer_username,
                            _,
                            ticket0,
                            Some(PeerResponse::Accept(Some(peer_username))),
                        ) => {
                            let to_kernel = session.kernel_tx.clone();
                            let account_manager = session.account_manager.clone();

                            let peer_cid = vconn.get_original_implicated_cid();
                            let this_cid = vconn.get_original_target_cid();

                            match account_manager
                                .register_hyperlan_p2p_at_endpoints(
                                    this_cid,
                                    peer_cid,
                                    peer_username,
                                )
                                .await
                            {
                                Ok(_) => {
                                    log::trace!(target: "citadel", "Success registering at endpoints");
                                    to_kernel.unbounded_send(NodeResult::PeerEvent(PeerEvent {
                                        event: PeerSignal::PostRegister(
                                            *vconn,
                                            peer_username.clone(),
                                            None,
                                            *ticket0,
                                            Some(PeerResponse::Accept(Some(peer_username.clone()))),
                                        ),
                                        ticket,
                                    }))?;
                                }

                                Err(err) => {
                                    log::error!(target: "citadel", "Unable to register at endpoints: {:?}", &err);
                                    to_kernel.unbounded_send(NodeResult::PeerEvent(PeerEvent {
                                        event: PeerSignal::SignalError(ticket, err.into_string()),
                                        ticket,
                                    }))?;
                                }
                            }

                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::PostConnect(
                            conn,
                            _,
                            Some(resp),
                            endpoint_security_settings,
                            udp_enabled,
                        ) => {
                            let accepted = matches!(resp, PeerResponse::Accept(_));
                            // TODO: handle non-accept case
                            // the connection was mutually accepted. Now, we must begin the KEM subroutine
                            if accepted {
                                return match conn {
                                    PeerConnectionType::HyperLANPeerToHyperLANPeer(
                                        original_implicated_cid,
                                        original_target_cid,
                                    ) => {
                                        // this implies this node is receiving an accept_request. As such, we need to NOT
                                        // forward the signal quite yet, and instead, begin the key-exchange process in order to
                                        // establish a working [PeerChannel] system that has a custom post-quantum key and toolset
                                        // unique to the session.
                                        //let mut state_container = inner_mut!(session.state_container);
                                        //let peer_cid = conn.get_original_implicated_cid();
                                        let mut peer_kem_state_container =
                                            PeerKemStateContainer::new(
                                                *endpoint_security_settings,
                                                *udp_enabled == UdpMode::Enabled,
                                            );

                                        let alice_constructor =
                                            return_if_none!(StackedRatchetConstructor::new_alice(
                                                ConstructorOpts::new_vec_init(
                                                    Some(endpoint_security_settings.crypto_params),
                                                    (endpoint_security_settings
                                                        .security_level
                                                        .value()
                                                        + 1)
                                                        as usize
                                                ),
                                                conn.get_original_target_cid(),
                                                0,
                                                Some(endpoint_security_settings.security_level)
                                            ));
                                        let transfer = return_if_none!(
                                            alice_constructor.stage0_alice(),
                                            "AliceConstructor None"
                                        );
                                        //log::trace!(target: "citadel", "0. Len: {}, {:?}", alice_pub_key.len(), &alice_pub_key[..10]);
                                        let msg_bytes =
                                            return_if_none!(transfer.serialize_to_vec());
                                        peer_kem_state_container.constructor =
                                            Some(alice_constructor);
                                        inner_mut_state!(session.state_container)
                                            .peer_kem_states
                                            .insert(
                                                *original_implicated_cid,
                                                peer_kem_state_container,
                                            );
                                        // finally, prepare the signal and send outbound
                                        // signal: PeerSignal, pqc: &Rc<PostQuantumContainer>, drill: &EntropyBank, ticket: Ticket, timestamp: i64
                                        let signal = PeerSignal::Kem(
                                            PeerConnectionType::HyperLANPeerToHyperLANPeer(
                                                *original_target_cid,
                                                *original_implicated_cid,
                                            ),
                                            KeyExchangeProcess::Stage0(
                                                msg_bytes,
                                                *endpoint_security_settings,
                                                *udp_enabled,
                                            ),
                                        );

                                        let stage0_peer_kem =
                                            packet_crafter::peer_cmd::craft_peer_signal(
                                                &sess_hyper_ratchet,
                                                signal,
                                                ticket,
                                                timestamp,
                                                security_level,
                                            );
                                        log::trace!(target: "citadel", "Sent peer KEM stage 0 outbound");
                                        // send to central server
                                        Ok(PrimaryProcessorResult::ReplyToSender(stage0_peer_kem))
                                    }

                                    _ => {
                                        log::error!(target: "citadel", "HyperWAN Functionality not yet enabled");
                                        Ok(PrimaryProcessorResult::Void)
                                    }
                                };
                            }
                        }

                        PeerSignal::Kem(conn, kep) => {
                            return match kep {
                                KeyExchangeProcess::Stage0(
                                    transfer,
                                    session_security_settings,
                                    udp_enabled,
                                ) => {
                                    log::trace!(target: "citadel", "RECV STAGE 0 PEER KEM");
                                    // We generate bob's pqc, as well as a nonce
                                    //let mut state_container = inner_mut!(session.state_container);
                                    //let this_cid = conn.get_original_target_cid();
                                    let peer_cid = conn.get_original_implicated_cid();
                                    let transfer_deser = return_if_none!(
                                        AliceToBobTransfer::deserialize_from(transfer)
                                    );
                                    let bob_constructor =
                                        return_if_none!(StackedRatchetConstructor::new_bob(
                                            conn.get_original_target_cid(),
                                            0,
                                            ConstructorOpts::new_vec_init(
                                                Some(session_security_settings.crypto_params),
                                                (session_security_settings.security_level.value()
                                                    + 1)
                                                    as usize
                                            ),
                                            transfer_deser
                                        ));
                                    let transfer = return_if_none!(bob_constructor.stage0_bob());

                                    let bob_transfer =
                                        return_if_none!(transfer.serialize_to_vector().ok());

                                    let signal = PeerSignal::Kem(
                                        conn.reverse(),
                                        KeyExchangeProcess::Stage1(bob_transfer, None),
                                    );

                                    let mut state_container_kem = PeerKemStateContainer::new(
                                        *session_security_settings,
                                        *udp_enabled == UdpMode::Enabled,
                                    );
                                    state_container_kem.constructor = Some(bob_constructor);
                                    inner_mut_state!(session.state_container)
                                        .peer_kem_states
                                        .insert(peer_cid, state_container_kem);

                                    let stage1_kem = packet_crafter::peer_cmd::craft_peer_signal(
                                        &sess_hyper_ratchet,
                                        signal,
                                        ticket,
                                        timestamp,
                                        security_level,
                                    );
                                    log::trace!(target: "citadel", "Sent stage 1 peer KEM");
                                    Ok(PrimaryProcessorResult::ReplyToSender(stage1_kem))
                                }

                                KeyExchangeProcess::Stage1(transfer, Some(bob_nat_info)) => {
                                    // Here, we finalize the creation of the pqc for alice, and then, generate the new toolset
                                    // The toolset gets encrypted to ensure the central server doesn't see the toolset. This is
                                    // to combat a "chinese communist hijack" scenario wherein a rogue government takes over our
                                    // central servers
                                    log::trace!(target: "citadel", "RECV STAGE 1 PEER KEM");
                                    //let security_level = session.security_level;

                                    let (
                                        hole_punch_compat_stream,
                                        channel,
                                        udp_rx_opt,
                                        sync_instant,
                                        encrypted_config_container,
                                        ticket_for_chan,
                                        needs_turn,
                                    ) = {
                                        let mut state_container =
                                            inner_mut_state!(session.state_container);
                                        let peer_cid = conn.get_original_implicated_cid();
                                        let this_cid = conn.get_original_target_cid();
                                        let mut kem_state = return_if_none!(state_container
                                            .peer_kem_states
                                            .remove(&peer_cid));
                                        let session_security_settings =
                                            kem_state.session_security_settings;
                                        let security_level =
                                            session_security_settings.security_level;
                                        let mut alice_constructor =
                                            return_if_none!(kem_state.constructor.take());
                                        let deser = return_if_none!(
                                            BobToAliceTransfer::deserialize_from(transfer),
                                            "bad deser"
                                        );
                                        alice_constructor
                                            .stage1_alice(BobToAliceTransferType::Default(deser))
                                            .map_err(|err| {
                                                NetworkError::Generic(err.to_string())
                                            })?;
                                        let hyper_ratchet = return_if_none!(
                                            alice_constructor.finish_with_custom_cid(this_cid)
                                        );
                                        let endpoint_hyper_ratchet = hyper_ratchet.clone();
                                        // now, create a new toolset and encrypt it
                                        // NOTE: when this toolset gets transmitted, it retains this_cid
                                        // As such, the other end MUST change the CID internally for BOTH
                                        // toolset AND the single drill
                                        let toolset = Toolset::new(this_cid, hyper_ratchet);
                                        // now, register the loaded PQC + toolset into the virtual conn
                                        let peer_crypto = PeerSessionCrypto::new(toolset, true);
                                        let vconn_type = VirtualConnectionType::LocalGroupPeer(
                                            this_cid, peer_cid,
                                        );
                                        let (needs_turn, bob_predicted_socket_addr) = bob_nat_info
                                            .generate_proper_listener_connect_addr(
                                                &session.local_nat_type,
                                            );
                                        log::trace!(target: "citadel", "[STUN] Peer public addr: {:?} || needs TURN? {}", &bob_predicted_socket_addr, needs_turn);
                                        let udp_rx_opt = kem_state.udp_channel_sender.rx.take();

                                        let channel = state_container
                                            .insert_new_peer_virtual_connection_as_endpoint(
                                                bob_predicted_socket_addr,
                                                session_security_settings,
                                                ticket,
                                                peer_cid,
                                                vconn_type,
                                                peer_crypto,
                                                session,
                                            );
                                        // load the channel now that the keys have been exchanged

                                        kem_state.local_is_initiator = true;
                                        state_container.peer_kem_states.insert(peer_cid, kem_state);
                                        log::trace!(target: "citadel", "Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);

                                        let header_time = header.timestamp.get();
                                        let (sync_instant, sync_time_ns) =
                                            calculate_sync_time(timestamp, header_time);
                                        // now that the virtual connection is created on this end, we need to do the same to the other end
                                        let signal = PeerSignal::Kem(
                                            conn.reverse(),
                                            KeyExchangeProcess::Stage2(sync_time_ns, None),
                                        );

                                        let endpoint_security_level =
                                            endpoint_hyper_ratchet.get_default_security_level();
                                        let hole_punch_compat_stream =
                                            ReliableOrderedCompatStream::new(
                                                return_if_none!(session.to_primary_stream.clone()),
                                                &mut state_container,
                                                peer_cid,
                                                endpoint_hyper_ratchet.clone(),
                                                endpoint_security_level,
                                            );
                                        let ticket_for_chan = state_container
                                            .outgoing_peer_connect_attempts
                                            .remove(&peer_cid);
                                        std::mem::drop(state_container);
                                        let encrypted_config_container =
                                            generate_hole_punch_crypt_container(
                                                endpoint_hyper_ratchet,
                                                SecurityLevel::Standard,
                                                peer_cid,
                                            );

                                        // we need to use the session pqc since this signal needs to get processed by the center node
                                        let stage2_kem_packet =
                                            packet_crafter::peer_cmd::craft_peer_signal(
                                                &sess_hyper_ratchet,
                                                signal,
                                                ticket,
                                                timestamp,
                                                security_level,
                                            );
                                        log::trace!(target: "citadel", "Sent stage 2 peer KEM");

                                        session.send_to_primary_stream(None, stage2_kem_packet)?;

                                        (
                                            hole_punch_compat_stream,
                                            channel,
                                            udp_rx_opt,
                                            sync_instant,
                                            encrypted_config_container,
                                            ticket_for_chan,
                                            needs_turn,
                                        )
                                    };

                                    let channel_signal =
                                        NodeResult::PeerChannelCreated(PeerChannelCreated {
                                            ticket: ticket_for_chan.unwrap_or(ticket),
                                            channel,
                                            udp_rx_opt,
                                        });

                                    if needs_turn && !cfg!(feature = "localhost-testing") {
                                        log::warn!(target: "citadel", "This p2p connection requires TURN-like routing");
                                        session.send_to_kernel(channel_signal)?;
                                    } else {
                                        let implicated_cid = session.implicated_cid.clone();
                                        let kernel_tx = session.kernel_tx.clone();
                                        // must send packet before registering app, otherwise, registration will fail
                                        let app = NetworkEndpoint::register(
                                            RelativeNodeType::Initiator,
                                            hole_punch_compat_stream,
                                        )
                                        .await
                                        .map_err(|err| NetworkError::Generic(err.to_string()))?;
                                        //session.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt)).ok()?;
                                        let client_config = session.client_config.clone();
                                        let _ = attempt_simultaneous_hole_punch(
                                            conn.reverse(),
                                            ticket,
                                            session.clone(),
                                            bob_nat_info.clone(),
                                            implicated_cid,
                                            kernel_tx,
                                            channel_signal,
                                            sync_instant,
                                            app,
                                            encrypted_config_container,
                                            client_config,
                                        )
                                        .await;
                                    }

                                    //let _ = hole_punch_future.await;
                                    Ok(PrimaryProcessorResult::Void)
                                }

                                KeyExchangeProcess::Stage2(sync_time_ns, Some(alice_nat_info)) => {
                                    // NEW UPDATE: now that we know the other side successfully created its toolset,
                                    // calculate sync time then begin the hole punch subroutine
                                    log::trace!(target: "citadel", "RECV STAGE 2 PEER KEM");
                                    let peer_cid = conn.get_original_implicated_cid();
                                    let this_cid = conn.get_original_target_cid();
                                    //let security_level = session.security_level;
                                    let (
                                        hole_punch_compat_stream,
                                        channel,
                                        udp_rx_opt,
                                        endpoint_hyper_ratchet,
                                        ticket_for_chan,
                                        needs_turn,
                                    ) = {
                                        let mut state_container =
                                            inner_mut_state!(session.state_container);
                                        let kem = return_if_none!(state_container
                                            .peer_kem_states
                                            .get_mut(&peer_cid));
                                        let session_security_settings =
                                            kem.session_security_settings;
                                        // since the AES-GCM was a success, we can now entrust that the toolset is perfectly symmetric to the
                                        // other side's toolset
                                        let bob_constructor =
                                            return_if_none!(kem.constructor.take());
                                        let udp_rx_opt = kem.udp_channel_sender.rx.take();
                                        let endpoint_hyper_ratchet = return_if_none!(
                                            bob_constructor.finish_with_custom_cid(this_cid)
                                        );
                                        let endpoint_security_level =
                                            endpoint_hyper_ratchet.get_default_security_level();
                                        let toolset =
                                            Toolset::new(this_cid, endpoint_hyper_ratchet.clone());
                                        let peer_crypto = PeerSessionCrypto::new(toolset, false);

                                        // create an endpoint vconn
                                        let vconn_type = VirtualConnectionType::LocalGroupPeer(
                                            this_cid, peer_cid,
                                        );
                                        let (needs_turn, alice_predicted_socket_addr) =
                                            alice_nat_info.generate_proper_listener_connect_addr(
                                                &session.local_nat_type,
                                            );
                                        log::trace!(target: "citadel", "[STUN] Peer public addr: {:?} || needs TURN? {}", &alice_predicted_socket_addr, needs_turn);
                                        let channel = state_container
                                            .insert_new_peer_virtual_connection_as_endpoint(
                                                alice_predicted_socket_addr,
                                                session_security_settings,
                                                ticket,
                                                peer_cid,
                                                vconn_type,
                                                peer_crypto,
                                                session,
                                            );

                                        log::trace!(target: "citadel", "Virtual connection forged on endpoint tuple {} -> {}", this_cid, peer_cid);
                                        // We can now send the channel to the kernel, where TURN traversal is immediantly available.
                                        // however, STUN-like traversal will proceed in the background
                                        //state_container.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt)).ok()?;
                                        let ticket_for_chan = state_container
                                            .outgoing_peer_connect_attempts
                                            .remove(&peer_cid);
                                        let hole_punch_compat_stream =
                                            ReliableOrderedCompatStream::new(
                                                return_if_none!(session.to_primary_stream.clone()),
                                                &mut state_container,
                                                peer_cid,
                                                endpoint_hyper_ratchet.clone(),
                                                endpoint_security_level,
                                            );
                                        (
                                            hole_punch_compat_stream,
                                            channel,
                                            udp_rx_opt,
                                            endpoint_hyper_ratchet,
                                            ticket_for_chan,
                                            needs_turn,
                                        )
                                    };

                                    let channel_signal =
                                        NodeResult::PeerChannelCreated(PeerChannelCreated {
                                            ticket: ticket_for_chan.unwrap_or(ticket),
                                            channel,
                                            udp_rx_opt,
                                        });

                                    if needs_turn && !cfg!(feature = "localhost-testing") {
                                        log::warn!(target: "citadel", "This p2p connection requires TURN-like routing");
                                        session.send_to_kernel(channel_signal)?;
                                    } else {
                                        let app = NetworkEndpoint::register(
                                            RelativeNodeType::Receiver,
                                            hole_punch_compat_stream,
                                        )
                                        .await
                                        .map_err(|err| NetworkError::Generic(err.to_string()))?;
                                        let encrypted_config_container =
                                            generate_hole_punch_crypt_container(
                                                endpoint_hyper_ratchet,
                                                SecurityLevel::Standard,
                                                peer_cid,
                                            );
                                        let diff = Duration::from_nanos(i64::abs(
                                            timestamp - *sync_time_ns,
                                        )
                                            as u64);
                                        let sync_instant = Instant::now() + diff;

                                        // session: HdpSession, expected_peer_cid: u64, peer_endpoint_addr: SocketAddr, implicated_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, sync_time: Instant
                                        let implicated_cid = session.implicated_cid.clone();
                                        let kernel_tx = session.kernel_tx.clone();
                                        let client_config = session.client_config.clone();

                                        let _ = attempt_simultaneous_hole_punch(
                                            conn.reverse(),
                                            ticket,
                                            session.clone(),
                                            alice_nat_info.clone(),
                                            implicated_cid,
                                            kernel_tx.clone(),
                                            channel_signal,
                                            sync_instant,
                                            app,
                                            encrypted_config_container,
                                            client_config,
                                        )
                                        .await;
                                    }

                                    //let _ = hole_punch_future.await;
                                    Ok(PrimaryProcessorResult::Void)
                                }

                                KeyExchangeProcess::HolePunchFailed => {
                                    log::trace!(target: "citadel", "RECV HolePunchFailed");
                                    // TODO/optional: for future consideration, but is currently not at all necessary
                                    Ok(PrimaryProcessorResult::Void)
                                }

                                _ => {
                                    log::error!(target: "citadel", "INVALID KEM signal");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            };
                        }

                        _ => {}
                    }

                    log::trace!(target: "citadel", "Forwarding PEER signal to kernel ...");
                    session
                        .kernel_tx
                        .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                            event: signal,
                            ticket,
                        }))?;
                    Ok(PrimaryProcessorResult::Void)
                } else {
                    process_signal_command_as_server(
                        session,
                        signal,
                        ticket,
                        sess_hyper_ratchet,
                        header,
                        timestamp,
                        security_level,
                    )
                    .await
                }
            }

            packet_flags::cmd::aux::peer_cmd::CHANNEL => Ok(PrimaryProcessorResult::Void),

            _ => {
                log::error!(target: "citadel", "Invalid peer auxiliary command");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}

async fn process_signal_command_as_server(
    sess_ref: &HdpSession,
    signal: PeerSignal,
    ticket: Ticket,
    sess_hyper_ratchet: StackedRatchet,
    header: LayoutVerified<&[u8], HdpHeader>,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = sess_ref;
    match signal {
        PeerSignal::Kem(conn, mut kep) => {
            // before just routing the signals, we also need to add socket information into intercepted stage1 and stage2 signals
            // to allow for STUN-like NAT traversal
            // this gives peer A the socket of peer B and vice versa

            let peer_nat = return_if_none!(
                session.adjacent_nat_type.clone(),
                "Adjacent NAT type not loaded"
            );
            let peer_remote_addr_visible_from_server = session.remote_peer;
            let tls_domain = return_if_none!(
                session.peer_only_connect_protocol.get(),
                "Peer only connect protocol not loaded"
            )
            .get_domain();

            let peer_nat_info = PeerNatInfo {
                peer_remote_addr_visible_from_server,
                peer_nat,
                tls_domain,
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
                log::error!(target: "citadel", "Error (equivalent CIDs)");
                return Ok(PrimaryProcessorResult::Void);
            }

            let res = sess_mgr.send_signal_to_peer_direct(
                conn.get_original_target_cid(),
                move |peer_hyper_ratchet| {
                    packet_crafter::peer_cmd::craft_peer_signal(
                        peer_hyper_ratchet,
                        signal_to,
                        ticket,
                        timestamp,
                        security_level,
                    )
                },
            );

            if let Err(err) = res {
                reply_to_sender_err(err, &sess_hyper_ratchet, ticket, timestamp, security_level)
            } else {
                Ok(PrimaryProcessorResult::Void)
            }
        }

        PeerSignal::PostRegister(
            peer_conn_type,
            username,
            peer_username_opt,
            _ticket_opt,
            peer_response,
        ) => {
            // check to see if the client is connected, and if not, send to HypernodePeerLayer
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => {
                    let implicated_cid = header.session_cid.get();
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour
                                                                            // if the peer response is some, then HyperLAN Client B responded
                    if let Some(peer_response) = peer_response {
                        // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                        super::server::post_register::handle_response_phase_post_register(
                            &mut *session.hypernode_peer_layer.inner.write().await,
                            peer_conn_type,
                            username,
                            peer_response,
                            ticket,
                            implicated_cid,
                            target_cid,
                            timestamp,
                            session,
                            &sess_hyper_ratchet,
                            security_level,
                        )
                        .await
                    } else {
                        // We route the signal from alice to bob. We send directly to Bob if FCM is not specified. If FCM is being used, then will route to target's FCM credentials
                        let target_cid = if let Some(peer_username) = peer_username_opt {
                            // since user did not know the CID, but only the CID, we have to find the cid
                            // here at the server
                            session
                                .account_manager
                                .get_persistence_handler()
                                .get_cid_by_username(peer_username.as_str())
                        } else {
                            // peer knew the cid, therefore, use target_cid
                            target_cid
                        };

                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase). No FCM
                        // NOTE: we MUST redefine peer_conn_type since it may be overwritten if only a username is given
                        let peer_conn_type = PeerConnectionType::HyperLANPeerToHyperLANPeer(
                            implicated_cid,
                            target_cid,
                        );

                        let mut peer_layer = session.hypernode_peer_layer.inner.write().await;

                        if let Some(ticket_new) =
                            peer_layer.check_simultaneous_register(implicated_cid, target_cid)
                        {
                            log::trace!(target: "citadel", "Simultaneous register detected! Simulating implicated_cid={} sent an accept_register to target={}", implicated_cid, target_cid);
                            // route signal to peer
                            let _ =
                                super::server::post_register::handle_response_phase_post_register(
                                    &mut peer_layer,
                                    peer_conn_type,
                                    username.clone(),
                                    PeerResponse::Accept(Some(username)),
                                    ticket_new,
                                    implicated_cid,
                                    target_cid,
                                    timestamp,
                                    session,
                                    &sess_hyper_ratchet,
                                    security_level,
                                )
                                .await?;
                            // rebound accept packet
                            let username = session
                                .account_manager
                                .get_username_by_cid(target_cid)
                                .await?;
                            let accept = PeerResponse::Accept(username.clone());
                            // TODO: get rid of multiple username fields
                            // we have to flip the ordering for here alone since the endpoint handler for this signal expects do
                            let peer_conn_type = PeerConnectionType::HyperLANPeerToHyperLANPeer(
                                target_cid,
                                implicated_cid,
                            );
                            let cmd = PeerSignal::PostRegister(
                                peer_conn_type,
                                username.clone().unwrap_or_default(),
                                username,
                                Some(ticket),
                                Some(accept),
                            );

                            let rebound_accept = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_hyper_ratchet,
                                cmd,
                                ticket,
                                timestamp,
                                security_level,
                            );
                            Ok(PrimaryProcessorResult::ReplyToSender(rebound_accept))
                        } else {
                            let to_primary_stream =
                                return_if_none!(session.to_primary_stream.clone());
                            let sess_mgr = session.session_manager.clone();
                            route_signal_and_register_ticket_forwards(
                                &mut peer_layer,
                                PeerSignal::PostRegister(
                                    peer_conn_type,
                                    username,
                                    None,
                                    Some(ticket),
                                    None,
                                ),
                                TIMEOUT,
                                implicated_cid,
                                target_cid,
                                timestamp,
                                ticket,
                                &to_primary_stream,
                                &sess_mgr,
                                &sess_hyper_ratchet,
                                security_level,
                            )
                            .await
                        }
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(
                    _implicated_cid,
                    _icid,
                    _target_cid,
                ) => {
                    log::warn!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::Deregister(peer_conn_type) => {
            // in deregistration, we send a Deregister signal to the peer (if connected)
            // then, delete the cid entry from the CNAC and save to the local FS
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let mut peer_layer_lock = session.hypernode_peer_layer.inner.write().await;
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    let mut register_event = false;

                    let dereg_result = if peer_layer_lock
                        .check_simulataneous_deregister(implicated_cid, target_cid)
                        .is_some()
                    {
                        // if the other peer is simultaneously deregistering, mark as Ok(())
                        log::info!(target: "citadel", "Simultaneous deregister detected");
                        Ok(())
                    } else {
                        register_event = true;
                        account_manager
                            .get_persistence_handler()
                            .deregister_p2p_as_server(implicated_cid, target_cid)
                            .await
                    };

                    match dereg_result {
                        Ok(_) => {
                            if register_event {
                                log::trace!(target: "citadel", "Registering dereg event");
                                peer_layer_lock
                                    .insert_tracked_posting(
                                        implicated_cid,
                                        Duration::from_secs(60),
                                        ticket,
                                        PeerSignal::DeregistrationSuccess(target_cid),
                                        |_| {},
                                    )
                                    .await;
                            }
                            let peer_alert_signal =
                                PeerSignal::DeregistrationSuccess(implicated_cid);
                            if !session_manager.send_signal_to_peer(
                                target_cid,
                                ticket,
                                peer_alert_signal,
                                timestamp,
                                security_level,
                            ) {
                                log::warn!(target: "citadel", "Unable to send packet to {} (maybe not connected)", target_cid);
                            }

                            // now, send a success packet to the client
                            let success_cmd = PeerSignal::DeregistrationSuccess(target_cid);
                            let rebound_packet = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_hyper_ratchet,
                                success_cmd,
                                ticket,
                                timestamp,
                                security_level,
                            );
                            Ok(PrimaryProcessorResult::ReplyToSender(rebound_packet))
                        }

                        Err(err) => {
                            log::error!(target: "citadel", "Unable to find peer");
                            // unable to find the peer
                            let error_signal = PeerSignal::SignalError(ticket, err.into_string());
                            let error_packet = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_hyper_ratchet,
                                error_signal,
                                ticket,
                                timestamp,
                                security_level,
                            );
                            Ok(PrimaryProcessorResult::ReplyToSender(error_packet))
                        }
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(
                    _implicated_cid,
                    _icid,
                    _target_cid,
                ) => {
                    log::warn!(target: "citadel", "HyperWAN functionality not yet enabled");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::PostConnect(
            peer_conn_type,
            _ticket_opt,
            peer_response,
            endpoint_security_level,
            udp_enabled,
        ) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    // TODO: Change timeouts. Create a better timeout system, in general
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60);
                    let mut peer_layer = session.hypernode_peer_layer.inner.write().await;
                    if let Some(peer_response) = peer_response {
                        super::server::post_connect::handle_response_phase_post_connect(
                            &mut peer_layer,
                            peer_conn_type,
                            ticket,
                            peer_response,
                            endpoint_security_level,
                            udp_enabled,
                            implicated_cid,
                            target_cid,
                            timestamp,
                            sess_ref,
                            &sess_hyper_ratchet,
                            security_level,
                        )
                        .await
                    } else {
                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase)
                        let to_primary_stream = return_if_none!(session.to_primary_stream.clone());
                        let sess_mgr = session.session_manager.clone();
                        if let Some(ticket_new) =
                            peer_layer.check_simultaneous_connect(implicated_cid, target_cid)
                        {
                            log::trace!(target: "citadel", "Simultaneous connect detected! Simulating implicated_cid={} sent an accept_connect to target={}", implicated_cid, target_cid);
                            log::trace!(target: "citadel", "Simultaneous connect: first_ticket: {} | sender expected ticket: {}", ticket_new, ticket);
                            // NOTE: Packet will rebound to sender, then, sender will locally send
                            // packet to the peer who first attempted a connect request
                            let _ =
                                super::server::post_connect::handle_response_phase_post_connect(
                                    &mut peer_layer,
                                    peer_conn_type,
                                    ticket_new,
                                    PeerResponse::Accept(None),
                                    endpoint_security_level,
                                    udp_enabled,
                                    implicated_cid,
                                    target_cid,
                                    timestamp,
                                    sess_ref,
                                    &sess_hyper_ratchet,
                                    security_level,
                                )
                                .await?;
                            Ok(PrimaryProcessorResult::Void)
                        } else {
                            route_signal_and_register_ticket_forwards(
                                &mut peer_layer,
                                PeerSignal::PostConnect(
                                    peer_conn_type,
                                    Some(ticket),
                                    None,
                                    endpoint_security_level,
                                    udp_enabled,
                                ),
                                TIMEOUT,
                                implicated_cid,
                                target_cid,
                                timestamp,
                                ticket,
                                &to_primary_stream,
                                &sess_mgr,
                                &sess_hyper_ratchet,
                                security_level,
                            )
                            .await
                        }
                    }
                }

                PeerConnectionType::HyperLANPeerToHyperWANPeer(
                    _implicated_cid,
                    _icid,
                    _target_cid,
                ) => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::Disconnect(peer_conn_type, resp) => {
            match peer_conn_type {
                PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    let state_container = inner_state!(session.state_container);
                    if let Some(v_conn) =
                        state_container.active_virtual_connections.get(&target_cid)
                    {
                        // ... but, we still want any messages already sent to be processed

                        let last_packet = v_conn.last_delivered_message_timestamp.clone();
                        let state_container_ref = session.state_container.clone();
                        let session_manager = session.session_manager.clone();

                        std::mem::drop(state_container);

                        let task = async move {
                            // note: this is w.r.t the server.
                            while let Some(ts) = last_packet.load(Ordering::SeqCst) {
                                if ts.elapsed() > Duration::from_millis(1500) {
                                    break;
                                }

                                tokio::time::sleep(Duration::from_millis(1500)).await;
                            }

                            log::trace!(target: "citadel", "[Peer Vconn @ Server] No packets received in the last 1500ms; will drop the virtual connection cleanly");
                            // once we're done waiting for packets to stop showing up, we can remove the container to end the underlying TCP stream
                            let mut state_container = inner_mut_state!(state_container_ref);
                            let _ = state_container
                                .active_virtual_connections
                                .remove(&target_cid)
                                .map(|v_conn| v_conn.is_active.store(false, Ordering::SeqCst));

                            let resp = Some(resp.unwrap_or(PeerResponse::Disconnected(format!(
                                "Peer {implicated_cid} closed the virtual connection to {target_cid}"
                            ))));
                            let signal_to_peer = PeerSignal::Disconnect(
                                PeerConnectionType::HyperLANPeerToHyperLANPeer(
                                    implicated_cid,
                                    target_cid,
                                ),
                                resp,
                            );
                            // now, remove target CID's v_conn to `implicated_cid`
                            std::mem::drop(state_container);
                            let _ = session_manager.disconnect_virtual_conn(
                                implicated_cid,
                                target_cid,
                                move |peer_hyper_ratchet| {
                                    // send signal to peer
                                    packet_crafter::peer_cmd::craft_peer_signal(
                                        peer_hyper_ratchet,
                                        signal_to_peer,
                                        ticket,
                                        timestamp,
                                        security_level,
                                    )
                                },
                            );
                        };

                        spawn!(task);

                        Ok(PrimaryProcessorResult::Void)
                    } else {
                        //reply_to_sender_err(format!("{} is not connected to {}", implicated_cid, target_cid), &sess_hyper_ratchet, ticket, timestamp, security_level)
                        // connection may already be dc'ed from another dc attempt. Just say nothing
                        Ok(PrimaryProcessorResult::Void)
                    }
                }

                _ => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::GetRegisteredPeers(hypernode_conn_type, _resp_opt, limit) => {
            match hypernode_conn_type {
                HypernodeConnectionType::HyperLANPeerToHyperLANServer(_implicated_cid) => {
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    log::trace!(target: "citadel", "[GetRegisteredPeers] Getting list");
                    let rebound_signal = if let Some(registered_local_clients) = account_manager
                        .get_registered_impersonal_cids(limit)
                        .await?
                    {
                        // TODO: Make check_online_status check database for database mode
                        let online_status =
                            session_manager.check_online_status(&registered_local_clients);
                        PeerSignal::GetRegisteredPeers(
                            hypernode_conn_type,
                            Some(PeerResponse::RegisteredCids(
                                registered_local_clients,
                                online_status,
                            )),
                            limit,
                        )
                    } else {
                        PeerSignal::GetRegisteredPeers(hypernode_conn_type, None, limit)
                    };

                    log::trace!(target: "citadel", "[GetRegisteredPeers] Done getting list");
                    reply_to_sender(
                        rebound_signal,
                        &sess_hyper_ratchet,
                        ticket,
                        timestamp,
                        security_level,
                    )
                }

                HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::GetMutuals(hypernode_conn_type, _resp_opt) => match hypernode_conn_type {
            HypernodeConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                let account_manager = session.account_manager.clone();
                let session_manager = session.session_manager.clone();

                log::trace!(target: "citadel", "[GetMutuals] Getting list");
                let rebound_signal = if let Some(mutuals) = account_manager
                    .get_hyperlan_peer_list(implicated_cid)
                    .await?
                {
                    let online_status = session_manager.check_online_status(&mutuals);
                    PeerSignal::GetMutuals(
                        hypernode_conn_type,
                        Some(PeerResponse::RegisteredCids(mutuals, online_status)),
                    )
                } else {
                    PeerSignal::GetMutuals(hypernode_conn_type, None)
                };

                log::trace!(target: "citadel", "[GetMutuals] Done getting list");
                reply_to_sender(
                    rebound_signal,
                    &sess_hyper_ratchet,
                    ticket,
                    timestamp,
                    security_level,
                )
            }

            HypernodeConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                log::error!(target: "citadel", "HyperWAN functionality not implemented");
                Ok(PrimaryProcessorResult::Void)
            }
        },

        PeerSignal::BroadcastConnected(_hypernode_conn_type) => Ok(PrimaryProcessorResult::Void),

        PeerSignal::PostFileUploadRequest(_peer_conn_type, _file_metadata, _ticket) => {
            Ok(PrimaryProcessorResult::Void)
        }

        PeerSignal::AcceptFileUploadRequest(_peer_conn_type, _ticket) => {
            Ok(PrimaryProcessorResult::Void)
        }

        PeerSignal::SignalError(ticket, err) => {
            // in this case, we delegate the error to the higher-level kernel to determine what to do
            session
                .kernel_tx
                .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::SignalError(ticket, err),
                    ticket,
                }))?;
            Ok(PrimaryProcessorResult::Void)
        }

        PeerSignal::SignalReceived(ticket) => {
            session
                .kernel_tx
                .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                    event: signal,
                    ticket,
                }))?;
            Ok(PrimaryProcessorResult::Void)
        }

        PeerSignal::DeregistrationSuccess(..) => Ok(PrimaryProcessorResult::Void),

        PeerSignal::DisconnectUDP(v_conn) => {
            // close this UDP channel
            inner_mut_state!(session.state_container).remove_udp_channel(v_conn.get_target_cid());
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

#[inline]
/// This just makes the repeated operation above cleaner. By itself does not send anything; must return the result of this closure directly
fn reply_to_sender(
    signal: PeerSignal,
    hyper_ratchet: &StackedRatchet,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        hyper_ratchet,
        signal,
        ticket,
        timestamp,
        security_level,
    );
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

fn reply_to_sender_err<E: ToString>(
    err: E,
    hyper_ratchet: &StackedRatchet,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    Ok(PrimaryProcessorResult::ReplyToSender(
        construct_error_signal(err, hyper_ratchet, ticket, timestamp, security_level),
    ))
}

fn construct_error_signal<E: ToString>(
    err: E,
    hyper_ratchet: &StackedRatchet,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> BytesMut {
    let err_signal = PeerSignal::SignalError(ticket, err.to_string());
    packet_crafter::peer_cmd::craft_peer_signal(
        hyper_ratchet,
        err_signal,
        ticket,
        timestamp,
        security_level,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn route_signal_and_register_ticket_forwards(
    peer_layer: &mut HyperNodePeerLayerInner,
    signal: PeerSignal,
    timeout: Duration,
    implicated_cid: u64,
    target_cid: u64,
    timestamp: i64,
    ticket: Ticket,
    to_primary_stream: &OutboundPrimaryStreamSender,
    sess_mgr: &HdpSessionManager,
    sess_hyper_ratchet: &StackedRatchet,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let sess_hyper_ratchet_2 = sess_hyper_ratchet.clone();
    let to_primary_stream = to_primary_stream.clone();

    // Give the target_cid 10 seconds to respond
    let res = sess_mgr.route_signal_primary(peer_layer, implicated_cid, target_cid, ticket, signal.clone(), move |peer_hyper_ratchet| {
        packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal.clone(), ticket, timestamp, security_level)
    }, timeout, move |stale_signal| {
        // on timeout, run this
        // TODO: Use latest ratchet, otherwise, may expire
        log::warn!(target: "citadel", "Running timeout closure. Sending error message to {}", implicated_cid);
        let error_packet = packet_crafter::peer_cmd::craft_peer_signal(&sess_hyper_ratchet_2, stale_signal, ticket, timestamp, security_level);
        let _ = to_primary_stream.unbounded_send(error_packet);
    }).await;

    // Then, we tell the implicated_cid's node that we have handled the message. However, the peer has yet to respond
    if let Err(err) = res {
        reply_to_sender_err(err, sess_hyper_ratchet, ticket, timestamp, security_level)
    } else {
        let received_signal = PeerSignal::SignalReceived(ticket);
        reply_to_sender(
            received_signal,
            sess_hyper_ratchet,
            ticket,
            timestamp,
            security_level,
        )
    }
}

// returns (true, status) if the process was a success, or (false, success) otherwise
#[allow(clippy::too_many_arguments)]
pub(crate) async fn route_signal_response(
    signal: PeerSignal,
    implicated_cid: u64,
    target_cid: u64,
    timestamp: i64,
    ticket: Ticket,
    peer_layer: &mut HyperNodePeerLayerInner,
    session: HdpSession,
    sess_hyper_ratchet: &StackedRatchet,
    on_route_finished: impl FnOnce(&HdpSession, &HdpSession, PeerSignal),
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    log::trace!(target: "citadel", "Routing signal {:?} | impl: {} | target: {}", signal, implicated_cid, target_cid);
    let sess_ref = &session;

    let res = session
        .session_manager
        .route_signal_response_primary(
            implicated_cid,
            target_cid,
            ticket,
            peer_layer,
            move |peer_hyper_ratchet| {
                packet_crafter::peer_cmd::craft_peer_signal(
                    peer_hyper_ratchet,
                    signal,
                    ticket,
                    timestamp,
                    security_level,
                )
            },
            move |peer_sess, original_posting| {
                // send a notification that the server forwarded the signal
                let received_signal = PeerSignal::SignalReceived(ticket);
                let ret = reply_to_sender(
                    received_signal,
                    sess_hyper_ratchet,
                    ticket,
                    timestamp,
                    security_level,
                );
                log::trace!(target: "citadel", "Running on_route_finished subroutine");
                //let mut peer_sess_ref = inner_mut!(peer_sess);
                on_route_finished(sess_ref, peer_sess, original_posting);
                ret
            },
        )
        .await;

    match res {
        Ok(ret) => ret,

        Err(err) => {
            log::warn!(target: "citadel", "Unable to route signal! {:?}", err);
            reply_to_sender_err(err, sess_hyper_ratchet, ticket, timestamp, security_level)
        }
    }
}
