//! Peer Command Packet Processor for Citadel Protocol
//!
//! This module handles the processing of peer command packets in the Citadel Protocol
//! network. It manages peer-to-peer communication, signal routing, and secure key
//! exchange between peers through the HyperLAN server.
//!
//! # Features
//!
//! - Peer command processing
//! - Signal routing and forwarding
//! - Secure key exchange
//! - Group broadcast handling
//! - Session state management
//! - Ticket tracking
//! - Error propagation
//!
//! # Important Notes
//!
//! - Requires server mediation
//! - All packets must be authenticated
//! - Handles both client and server roles
//! - Manages peer session states
//! - Supports group operations
//! - Implements error handling
//!
//! # Related Components
//!
//! - `CitadelSession`: Session management
//! - `PeerSignal`: Signal processing
//! - `HyperNodePeerLayerInner`: Peer layer
//! - `StackedRatchet`: Cryptographic operations
//! - `StateContainer`: State management

use std::sync::atomic::Ordering;

use bytes::BytesMut;

use citadel_crypt::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
use citadel_crypt::prelude::ConstructorOpts;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::toolset::Toolset;
use citadel_types::proto::UdpMode;
use citadel_user::backend::BackendType;
use citadel_user::serialization::SyncIO;
use netbeam::sync::RelativeNodeType;

use crate::error::NetworkError;
use crate::proto::node_result::{PeerChannelCreated, PeerEvent};
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::packet_processor::includes::*;
use crate::proto::packet_processor::peer::{group_broadcast, send_dc_signal_peer};
use crate::proto::packet_processor::preconnect_packet::{
    calculate_sync_time, generate_hole_punch_crypt_container,
};
use crate::proto::packet_processor::primary_group_packet::{
    get_orientation_safe_ratchet, get_resp_target_cid,
};
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::p2p_conn_handler::attempt_simultaneous_hole_punch;
use crate::proto::peer::peer_crypt::{KeyExchangeProcess, PeerNatInfo};
use crate::proto::peer::peer_layer::{
    CitadelNodePeerLayerInner, ClientConnectionType, PeerConnectionType, PeerResponse, PeerSignal,
};
use crate::proto::remote::Ticket;
use crate::proto::session_manager::CitadelSessionManager;
use crate::proto::state_container::OutgoingPeerConnectionAttempt;
use crate::proto::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use netbeam::sync::network_endpoint::NetworkEndpoint;

#[allow(unused_results)]
/// Insofar, there is no use of endpoint-to-endpoint encryption for PEER_CMD packets because they are mediated between the
/// HyperLAN client and the HyperLAN Server
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_orig.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_peer_cmd<R: Ratchet>(
    session_orig: &CitadelSession<R>,
    aux_cmd: u8,
    packet: HdpPacket,
    header_entropy_bank_version: u32,
    endpoint_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    // ALL PEER_CMD packets require that the current session contain a CNAC (not anymore since switching to async)
    let session = session_orig.clone();
    let (header, payload, _peer_addr, _) = packet.decompose();

    let (session_cid, sess_ratchet, payload, security_level) = {
        // Some PEER_CMD packets get encrypted using the endpoint crypto

        log::trace!(target: "citadel", "RECV PEER CMD packet (proxy: {})", endpoint_cid_info.is_some());
        let state_container = inner_state!(session.state_container);
        let session_cid = return_if_none!(session.session_cid.get());
        let sess_ratchet = return_if_none!(
            get_orientation_safe_ratchet(
                header_entropy_bank_version,
                &state_container,
                endpoint_cid_info
            ),
            "Unable to obtain peer HR (P_CMD_PKT)"
        );

        let (header, payload) = return_if_none!(
            validation::aead::validate_custom(&sess_ratchet, &header, payload),
            "Unable to validate peer CMD packet"
        );
        let security_level = header.security_level.into();
        log::trace!(target: "citadel", "PEER CMD packet authenticated");
        (session_cid, sess_ratchet, payload, security_level)
    };

    let task = async move {
        let session = &session;
        // we can unwrap below safely since the header layout has already been verified
        let header = Ref::new(&*header).unwrap();

        match aux_cmd {
            packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST => {
                group_broadcast::process_group_broadcast(
                    session,
                    header,
                    &payload[..],
                    &sess_ratchet,
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
                        PeerSignal::Disconnect {
                            peer_conn_type: vconn,
                            disconnect_response: resp,
                        } => {
                            // below line is confusing. The logic is answered in the server block for PeerSignal::Disconnect
                            let target = resp
                                .as_ref()
                                .map(|_| vconn.get_original_session_cid())
                                .unwrap_or_else(|| vconn.get_original_target_cid());
                            let mut state_container = inner_mut_state!(session.state_container);
                            if let Some(v_conn) =
                                state_container.active_virtual_connections.remove(&target)
                            {
                                v_conn.is_active.store(false, Ordering::SeqCst);
                                //prevent further messages from being sent from this node
                            }

                            session.send_to_kernel(NodeResult::PeerEvent(PeerEvent {
                                event: signal,
                                ticket,
                                session_cid,
                            }))?;
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::DisconnectUDP { peer_conn_type } => {
                            let target_cid = return_if_none!(get_resp_target_cid(
                                &peer_conn_type.as_virtual_connection()
                            ));
                            inner_mut_state!(session.state_container)
                                .remove_udp_channel(target_cid);
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::DeregistrationSuccess { peer_conn_type } => {
                            let peer_cid = peer_conn_type.get_original_target_cid();
                            log::trace!(target: "citadel", "[Deregistration] about to remove peer {peer_cid} from {session_cid} at the endpoint");
                            let acc_mgr = &session.account_manager;
                            let kernel_tx = &session.kernel_tx;

                            if (acc_mgr
                                .get_persistence_handler()
                                .deregister_p2p_as_client(session_cid, peer_cid)
                                .await?)
                                .is_none()
                            {
                                log::warn!(target: "citadel", "Unable to remove local group peer {peer_cid}");
                            }

                            kernel_tx.unbounded_send(NodeResult::PeerEvent(PeerEvent {
                                event: PeerSignal::DeregistrationSuccess {
                                    peer_conn_type: *peer_conn_type,
                                },
                                ticket,
                                session_cid,
                            }))?;
                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::PostRegister {
                            peer_conn_type: vconn,
                            inviter_username: _peer_username,
                            invitee_username: _,
                            ticket_opt: ticket0,
                            invitee_response: Some(PeerResponse::Accept(Some(peer_username))),
                        } => {
                            let to_kernel = session.kernel_tx.clone();
                            let account_manager = session.account_manager.clone();

                            let peer_cid = vconn.get_original_session_cid();
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
                                        event: PeerSignal::PostRegister {
                                            peer_conn_type: *vconn,
                                            inviter_username: peer_username.clone(),
                                            invitee_username: None,
                                            ticket_opt: *ticket0,
                                            invitee_response: Some(PeerResponse::Accept(Some(
                                                peer_username.clone(),
                                            ))),
                                        },
                                        ticket,
                                        session_cid,
                                    }))?;
                                }

                                Err(err) => {
                                    log::error!(target: "citadel", "Unable to register at endpoints: {:?}", &err);
                                    to_kernel.unbounded_send(NodeResult::PeerEvent(PeerEvent {
                                        event: PeerSignal::SignalError {
                                            ticket,
                                            error: err.into_string(),
                                            peer_connection_type: vconn.reverse(),
                                        },
                                        ticket,
                                        session_cid,
                                    }))?;
                                }
                            }

                            return Ok(PrimaryProcessorResult::Void);
                        }

                        PeerSignal::PostConnect {
                            peer_conn_type: conn,
                            ticket_opt: _,
                            invitee_response: Some(resp),
                            session_security_settings: endpoint_security_settings,
                            udp_mode: udp_enabled,
                            session_password: _,
                        } => {
                            log::trace!(target: "citadel", "Handling peer connect");
                            let accepted = matches!(resp, PeerResponse::Accept(_));
                            // the connection was mutually accepted. Now, we must begin the KEM subroutine
                            if accepted {
                                return match conn {
                                    PeerConnectionType::LocalGroupPeer {
                                        session_cid: original_session_cid,
                                        peer_cid: original_target_cid,
                                    } => {
                                        // this implies this node is receiving an accept_request. As such, we need to NOT
                                        // forward the signal quite yet, and instead, begin the key-exchange process in order to
                                        // establish a working [PeerChannel] system that has a custom post-quantum key and toolset
                                        // unique to the session.
                                        //let mut state_container = inner_mut!(session.state_container);
                                        //let peer_cid = conn.get_original_session_cid();

                                        let alice_constructor = return_if_none!(
                                            <R::Constructor as EndpointRatchetConstructor<R>>::new_alice(
                                                ConstructorOpts::new_vec_init(
                                                    Some(endpoint_security_settings.crypto_params),
                                                    endpoint_security_settings.security_level
                                                ),
                                                conn.get_original_target_cid(),
                                                0,
                                            )
                                        );
                                        let transfer = return_if_none!(
                                            alice_constructor.stage0_alice(),
                                            "AliceConstructor None"
                                        );
                                        //log::trace!(target: "citadel", "0. Len: {}, {:?}", alice_pub_key.len(), &alice_pub_key[..10]);
                                        let msg_bytes = return_if_none!(
                                            SyncIO::serialize_to_vector(&transfer).ok()
                                        );

                                        let mut state_container =
                                            inner_mut_state!(session.state_container);

                                        let session_password = state_container
                                            .get_session_password(conn.get_original_session_cid())
                                            .cloned();
                                        if session_password.is_none() {
                                            log::error!(target: "citadel", "The session password locally is set to None. This is a development issue, please report");
                                        }

                                        let session_password = session_password.unwrap_or_default();
                                        let mut peer_kem_state_container =
                                            PeerKemStateContainer::new(
                                                *endpoint_security_settings,
                                                *udp_enabled == UdpMode::Enabled,
                                                session_password.clone(),
                                            );

                                        peer_kem_state_container.constructor =
                                            Some(alice_constructor);

                                        state_container.peer_kem_states.insert(
                                            *original_session_cid,
                                            peer_kem_state_container,
                                        );

                                        drop(state_container);
                                        // finally, prepare the signal and send outbound
                                        // signal: PeerSignal, pqc: &Rc<PostQuantumContainer>, entropy_bank: &EntropyBank, ticket: Ticket, timestamp: i64
                                        let signal = PeerSignal::Kex {
                                            peer_conn_type: PeerConnectionType::LocalGroupPeer {
                                                session_cid: *original_target_cid,
                                                peer_cid: *original_session_cid,
                                            },
                                            kex_payload: KeyExchangeProcess::Stage0(
                                                msg_bytes,
                                                *endpoint_security_settings,
                                                *udp_enabled,
                                            ),
                                        };

                                        let stage0_peer_kem =
                                            packet_crafter::peer_cmd::craft_peer_signal(
                                                &sess_ratchet,
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
                            } else {
                                // Send error to kernel for peer connect fail. Reason: did not accept
                                session.send_to_kernel(NodeResult::PeerEvent(PeerEvent {
                                    event: PeerSignal::SignalError {
                                        ticket,
                                        error: "Peer did not accept connection".to_string(),
                                        peer_connection_type: conn.reverse(),
                                    },
                                    ticket,
                                    session_cid,
                                }))?;
                            }
                        }

                        PeerSignal::Kex {
                            peer_conn_type: conn,
                            kex_payload: kep,
                        } => {
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
                                    let peer_cid = conn.get_original_session_cid();
                                    let transfer_deser = return_if_none!(
                                        SyncIO::deserialize_from_vector(transfer).ok()
                                    );

                                    let mut state_container =
                                        inner_mut_state!(session.state_container);

                                    let session_password =
                                        state_container.get_session_password(peer_cid).cloned();
                                    if session_password.is_none() {
                                        log::error!(target: "citadel", "The session password locally is set to None. This is a development issue, please report");
                                    }

                                    let session_password = session_password.unwrap_or_default();

                                    let mut bob_constructor = return_if_none!(
                                        <R::Constructor as EndpointRatchetConstructor<R>>::new_bob(
                                            conn.get_original_target_cid(),
                                            ConstructorOpts::new_vec_init(
                                                Some(session_security_settings.crypto_params),
                                                session_security_settings.security_level,
                                            ),
                                            transfer_deser,
                                            session_password.as_ref(),
                                        )
                                    );
                                    let transfer = return_if_none!(bob_constructor.stage0_bob());
                                    let bob_transfer =
                                        return_if_none!(transfer.serialize_to_vector().ok());

                                    let local_is_file_transfer_compat = matches!(
                                        session.account_manager.get_backend_type(),
                                        BackendType::Filesystem(..)
                                    );

                                    let signal = PeerSignal::Kex {
                                        peer_conn_type: conn.reverse(),
                                        kex_payload: KeyExchangeProcess::Stage1(
                                            bob_transfer,
                                            None,
                                            local_is_file_transfer_compat,
                                        ),
                                    };

                                    let mut state_container_kem = PeerKemStateContainer::new(
                                        *session_security_settings,
                                        *udp_enabled == UdpMode::Enabled,
                                        session_password,
                                    );
                                    state_container_kem.constructor = Some(bob_constructor);
                                    state_container
                                        .peer_kem_states
                                        .insert(peer_cid, state_container_kem);

                                    drop(state_container);
                                    let stage1_kem = packet_crafter::peer_cmd::craft_peer_signal(
                                        &sess_ratchet,
                                        signal,
                                        ticket,
                                        timestamp,
                                        security_level,
                                    );
                                    log::trace!(target: "citadel", "Sent stage 1 peer KEM");
                                    Ok(PrimaryProcessorResult::ReplyToSender(stage1_kem))
                                }

                                KeyExchangeProcess::Stage1(
                                    transfer,
                                    Some(bob_nat_info),
                                    peer_file_transfer_compat,
                                ) => {
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
                                        local_outgoing_attempt_metadata,
                                        needs_turn,
                                        kem_session_security_settings,
                                        peer_cid,
                                    ) = {
                                        let mut state_container =
                                            inner_mut_state!(session.state_container);
                                        let peer_cid = conn.get_original_session_cid();
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
                                            SyncIO::deserialize_from_vector(transfer).ok(),
                                            "bad deser"
                                        );

                                        if let Err(err) = alice_constructor.stage1_alice(
                                            deser,
                                            kem_state.session_password.as_ref(),
                                        ) {
                                            log::warn!(target: "citadel", "Failed to complete key exchange for {session_cid} | Wrong session passwords? Err: {err:?}");
                                            send_dc_signal_peer(
                                                session,
                                                ticket,
                                                format!("{err:?}"),
                                            )?;
                                            // Send the error signal to the peer
                                            let error_signal = PeerSignal::SignalError {
                                                ticket,
                                                error: err.into_string(),
                                                peer_connection_type: conn.reverse(),
                                            };
                                            let error_packet =
                                                packet_crafter::peer_cmd::craft_peer_signal(
                                                    &sess_ratchet,
                                                    error_signal,
                                                    ticket,
                                                    timestamp,
                                                    security_level,
                                                );
                                            return Ok(PrimaryProcessorResult::ReplyToSender(
                                                error_packet,
                                            ));
                                        }
                                        let ratchet = return_if_none!(
                                            alice_constructor.finish_with_custom_cid(this_cid)
                                        );
                                        let endpoint_ratchet = ratchet.clone();
                                        // now, create a new toolset and encrypt it
                                        // NOTE: when this toolset gets transmitted, it retains this_cid
                                        // As such, the other end MUST change the CID internally for BOTH
                                        // toolset AND the single entropy_bank
                                        let toolset = Toolset::new(this_cid, ratchet);
                                        // now, register the loaded PQC + toolset into the virtual conn
                                        // Use CID comparison as deterministic tie-breaker for is_initiator
                                        // This ensures consistent behavior even under race conditions
                                        let local_is_initiator = this_cid > peer_cid;
                                        log::trace!(target: "citadel", "P2P session {this_cid} <-> {peer_cid}: local_is_initiator={local_is_initiator} (CID comparison)");
                                        let peer_crypto =
                                            PeerSessionCrypto::new(toolset, local_is_initiator);
                                        let vconn_type = VirtualConnectionType::LocalGroupPeer {
                                            session_cid: this_cid,
                                            peer_cid,
                                        };
                                        let (needs_turn, bob_predicted_socket_addr) = bob_nat_info
                                            .generate_proper_listener_connect_addr(
                                                &session.local_nat_type,
                                            );
                                        log::trace!(target: "citadel", "[STUN] Peer public addr: {:?} || needs TURN? {}", &bob_predicted_socket_addr, needs_turn);
                                        let udp_rx_opt = kem_state.udp_channel_sender.rx.take();
                                        let local_is_file_transfer_compat = matches!(
                                            session.account_manager.get_backend_type(),
                                            BackendType::Filesystem(..)
                                        );

                                        let channel = state_container.create_virtual_connection(
                                            //bob_predicted_socket_addr,
                                            session_security_settings,
                                            ticket,
                                            peer_cid,
                                            vconn_type,
                                            peer_crypto,
                                            session,
                                            local_is_file_transfer_compat
                                                && *peer_file_transfer_compat,
                                        );
                                        // load the channel now that the keys have been exchanged

                                        kem_state.local_is_initiator = true;
                                        state_container.peer_kem_states.insert(peer_cid, kem_state);
                                        log::trace!(target: "citadel", "Virtual connection forged on endpoint tuple {this_cid} -> {peer_cid}");

                                        let header_time = header.timestamp.get();
                                        let (sync_instant, sync_time_ns) =
                                            calculate_sync_time(timestamp, header_time);
                                        // now that the virtual connection is created on this end, we need to do the same to the other end
                                        let signal = PeerSignal::Kex {
                                            peer_conn_type: conn.reverse(),
                                            kex_payload: KeyExchangeProcess::Stage2(
                                                sync_time_ns,
                                                None,
                                                local_is_file_transfer_compat,
                                            ),
                                        };

                                        let endpoint_security_level =
                                            endpoint_ratchet.get_default_security_level();
                                        let hole_punch_compat_stream =
                                            ReliableOrderedCompatStream::<R>::new(
                                                return_if_none!(session.to_primary_stream.clone()),
                                                &mut state_container,
                                                peer_cid,
                                                endpoint_ratchet.clone(),
                                                endpoint_security_level,
                                            );
                                        let local_outgoing_attempt_metadata = state_container
                                            .outgoing_peer_connect_attempts
                                            .remove(&peer_cid);
                                        drop(state_container);
                                        let stun_servers = session.stun_servers.clone();
                                        let encrypted_config_container =
                                            generate_hole_punch_crypt_container(
                                                endpoint_ratchet,
                                                SecurityLevel::Standard,
                                                peer_cid,
                                                stun_servers,
                                            );

                                        // we need to use the session pqc since this signal needs to get processed by the center node
                                        let stage2_kem_packet =
                                            packet_crafter::peer_cmd::craft_peer_signal(
                                                &sess_ratchet,
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
                                            local_outgoing_attempt_metadata,
                                            needs_turn,
                                            session_security_settings,
                                            peer_cid,
                                        )
                                    };

                                    let udp_mode = if udp_rx_opt.is_some() {
                                        UdpMode::Enabled
                                    } else {
                                        UdpMode::Disabled
                                    };

                                    // For initiators: use ticket from outgoing_peer_connect_attempts
                                    // For responders (shouldn't happen in Stage1, but for robustness): use fallback
                                    let (init_ticket, session_security_settings) = if let Some(
                                        OutgoingPeerConnectionAttempt {
                                            ticket: stored_ticket,
                                            session_security_settings: stored_settings,
                                        },
                                    ) =
                                        local_outgoing_attempt_metadata
                                    {
                                        (stored_ticket, stored_settings)
                                    } else {
                                        // Fallback case: use packet header ticket and KEM state settings
                                        log::trace!(target: "citadel", "Using fallback ticket for Stage1 (peer_cid: {peer_cid})");
                                        (ticket, kem_session_security_settings)
                                    };

                                    let channel_signal =
                                        NodeResult::PeerChannelCreated(PeerChannelCreated {
                                            ticket: init_ticket,
                                            channel: channel.into(),
                                            udp_rx_opt,
                                        });

                                    if needs_turn && !cfg!(feature = "localhost-testing") {
                                        log::warn!(target: "citadel", "This p2p connection requires TURN-like routing");
                                        session.send_to_kernel(channel_signal)?;
                                    } else {
                                        let session_cid = session.session_cid.clone();
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
                                            session_cid,
                                            kernel_tx,
                                            channel_signal,
                                            sync_instant,
                                            app,
                                            encrypted_config_container,
                                            client_config,
                                            udp_mode,
                                            session_security_settings,
                                        )
                                        .await;
                                    }

                                    //let _ = hole_punch_future.await;
                                    Ok(PrimaryProcessorResult::Void)
                                }

                                KeyExchangeProcess::Stage2(
                                    sync_time_ns,
                                    Some(alice_nat_info),
                                    peer_file_transfer_compat,
                                ) => {
                                    // NEW UPDATE: now that we know the other side successfully created its toolset,
                                    // calculate sync time then begin the hole punch subroutine
                                    log::trace!(target: "citadel", "RECV STAGE 2 PEER KEM");
                                    let peer_cid = conn.get_original_session_cid();
                                    let this_cid = conn.get_original_target_cid();
                                    //let security_level = session.security_level;
                                    let (
                                        hole_punch_compat_stream,
                                        channel,
                                        udp_rx_opt,
                                        endpoint_ratchet,
                                        local_outgoing_connection_attempt_metadata,
                                        needs_turn,
                                        kem_session_security_settings,
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
                                        let endpoint_ratchet = return_if_none!(
                                            bob_constructor.finish_with_custom_cid(this_cid)
                                        );
                                        let endpoint_security_level =
                                            endpoint_ratchet.get_default_security_level();
                                        let toolset =
                                            Toolset::new(this_cid, endpoint_ratchet.clone());
                                        // Use CID comparison as deterministic tie-breaker for is_initiator
                                        // This ensures consistent behavior even under race conditions
                                        let local_is_initiator = this_cid > peer_cid;
                                        log::trace!(target: "citadel", "P2P session {this_cid} <-> {peer_cid}: local_is_initiator={local_is_initiator} (CID comparison)");
                                        let peer_crypto =
                                            PeerSessionCrypto::new(toolset, local_is_initiator);

                                        // create an endpoint vconn
                                        let vconn_type = VirtualConnectionType::LocalGroupPeer {
                                            session_cid: this_cid,
                                            peer_cid,
                                        };
                                        let (needs_turn, alice_predicted_socket_addr) =
                                            alice_nat_info.generate_proper_listener_connect_addr(
                                                &session.local_nat_type,
                                            );
                                        let local_is_file_transfer_compat = matches!(
                                            session.account_manager.get_backend_type(),
                                            BackendType::Filesystem(..)
                                        );

                                        log::trace!(target: "citadel", "[STUN] Peer public addr: {:?} || needs TURN? {}", &alice_predicted_socket_addr, needs_turn);

                                        let channel = state_container.create_virtual_connection(
                                            //alice_predicted_socket_addr,
                                            session_security_settings,
                                            ticket,
                                            peer_cid,
                                            vconn_type,
                                            peer_crypto,
                                            session,
                                            local_is_file_transfer_compat
                                                && *peer_file_transfer_compat,
                                        );

                                        log::trace!(target: "citadel", "Virtual connection forged on endpoint tuple {this_cid} -> {peer_cid}");
                                        // We can now send the channel to the kernel, where TURN traversal is immediantly available.
                                        // however, STUN-like traversal will proceed in the background
                                        //state_container.kernel_tx.unbounded_send(HdpServerResult::PeerChannelCreated(ticket, channel, udp_rx_opt)).ok()?;
                                        let local_outgoing_connection_attempt_metadata =
                                            state_container
                                                .outgoing_peer_connect_attempts
                                                .remove(&peer_cid);
                                        let hole_punch_compat_stream =
                                            ReliableOrderedCompatStream::<R>::new(
                                                return_if_none!(session.to_primary_stream.clone()),
                                                &mut state_container,
                                                peer_cid,
                                                endpoint_ratchet.clone(),
                                                endpoint_security_level,
                                            );
                                        (
                                            hole_punch_compat_stream,
                                            channel,
                                            udp_rx_opt,
                                            endpoint_ratchet,
                                            local_outgoing_connection_attempt_metadata,
                                            needs_turn,
                                            session_security_settings,
                                        )
                                    };

                                    let udp_mode = if udp_rx_opt.is_some() {
                                        UdpMode::Enabled
                                    } else {
                                        UdpMode::Disabled
                                    };

                                    // For initiators: use ticket from outgoing_peer_connect_attempts
                                    // For responders: use ticket from packet header (they didn't initiate, so no entry exists)
                                    let (init_ticket, session_security_settings) = if let Some(
                                        OutgoingPeerConnectionAttempt {
                                            ticket: stored_ticket,
                                            session_security_settings: stored_settings,
                                        },
                                    ) =
                                        local_outgoing_connection_attempt_metadata
                                    {
                                        (stored_ticket, stored_settings)
                                    } else {
                                        // Responder case: use packet header ticket and KEM state settings
                                        log::trace!(target: "citadel", "Using fallback ticket for responder (peer_cid: {peer_cid})");
                                        (ticket, kem_session_security_settings)
                                    };

                                    let channel_signal =
                                        NodeResult::PeerChannelCreated(PeerChannelCreated {
                                            ticket: init_ticket,
                                            channel: channel.into(),
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
                                        let stun_servers = session.stun_servers.clone();
                                        let encrypted_config_container =
                                            generate_hole_punch_crypt_container(
                                                endpoint_ratchet,
                                                SecurityLevel::Standard,
                                                peer_cid,
                                                stun_servers,
                                            );
                                        let diff = Duration::from_nanos(i64::abs(
                                            timestamp - *sync_time_ns,
                                        )
                                            as u64);
                                        let sync_instant = Instant::now() + diff;

                                        // session: HdpSession, expected_peer_cid: u64, peer_endpoint_addr: SocketAddr, session_cid: Arc<Atomic<Option<u64>>>, kernel_tx: UnboundedSender<HdpServerResult>, sync_time: Instant
                                        let session_cid = session.session_cid.clone();
                                        let kernel_tx = session.kernel_tx.clone();
                                        let client_config = session.client_config.clone();

                                        let _ = attempt_simultaneous_hole_punch(
                                            conn.reverse(),
                                            ticket,
                                            session.clone(),
                                            alice_nat_info.clone(),
                                            session_cid,
                                            kernel_tx.clone(),
                                            channel_signal,
                                            sync_instant,
                                            app,
                                            encrypted_config_container,
                                            client_config,
                                            udp_mode,
                                            session_security_settings,
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

                        // Client-side handling for incoming PostConnect request with no response.
                        // This handles the race condition where both peers send PostConnect
                        // simultaneously and the server-side simultaneous detection fails.
                        // We use a CID-based tiebreaker: only the side with the lower CID auto-accepts.
                        PeerSignal::PostConnect {
                            peer_conn_type: conn,
                            invitee_response: None,
                            session_security_settings: endpoint_security_settings,
                            udp_mode: udp_enabled,
                            ..
                        } => {
                            let peer_cid = conn.get_original_session_cid();
                            let has_outgoing = {
                                let state_container = inner_state!(session.state_container);
                                state_container
                                    .outgoing_peer_connect_attempts
                                    .contains_key(&peer_cid)
                            };

                            if has_outgoing {
                                // Both sides are trying to connect to each other.
                                // Use CID-based tiebreaker: lower CID auto-accepts.
                                let we_are_lower = session_cid < peer_cid;
                                if we_are_lower {
                                    log::trace!(target: "citadel", "Simultaneous connect detected client-side: {session_cid} auto-accepting incoming PostConnect from {peer_cid}");

                                    // Store peer KEM state for the incoming connection
                                    let mut state_container =
                                        inner_mut_state!(session.state_container);
                                    let session_password = state_container
                                        .get_session_password(peer_cid)
                                        .cloned()
                                        .unwrap_or_default();
                                    let peer_kem_state_container = PeerKemStateContainer::new(
                                        *endpoint_security_settings,
                                        *udp_enabled == UdpMode::Enabled,
                                        session_password,
                                    );
                                    state_container
                                        .peer_kem_states
                                        .insert(peer_cid, peer_kem_state_container);
                                    drop(state_container);

                                    // Send Accept response back to server
                                    let accept_signal = PeerSignal::PostConnect {
                                        peer_conn_type: conn.reverse(),
                                        ticket_opt: Some(ticket),
                                        invitee_response: Some(PeerResponse::Accept(None)),
                                        session_security_settings: *endpoint_security_settings,
                                        udp_mode: *udp_enabled,
                                        session_password: None,
                                    };

                                    let packet = packet_crafter::peer_cmd::craft_peer_signal(
                                        &sess_ratchet,
                                        accept_signal,
                                        ticket,
                                        timestamp,
                                        security_level,
                                    );
                                    return Ok(PrimaryProcessorResult::ReplyToSender(packet));
                                } else {
                                    log::trace!(target: "citadel", "Simultaneous connect detected client-side: {session_cid} deferring to {peer_cid} (lower CID)");
                                    // Higher CID ignores - the lower CID side will handle it
                                    return Ok(PrimaryProcessorResult::Void);
                                }
                            }
                            // Not simultaneous connect - fall through to forward to kernel
                        }

                        _ => {}
                    }

                    log::trace!(target: "citadel", "Forwarding signal {signal:?} to kernel");

                    session
                        .kernel_tx
                        .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                            event: signal,
                            ticket,
                            session_cid,
                        }))?;
                    Ok(PrimaryProcessorResult::Void)
                } else {
                    process_signal_command_as_server(
                        session,
                        signal,
                        ticket,
                        sess_ratchet,
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

async fn process_signal_command_as_server<R: Ratchet>(
    sess_ref: &CitadelSession<R>,
    signal: PeerSignal,
    ticket: Ticket,
    sess_ratchet: R,
    header: Ref<&[u8], HdpHeader>,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = sess_ref;
    match signal {
        PeerSignal::Kex {
            peer_conn_type: conn,
            kex_payload: mut kep,
        } => {
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
                KeyExchangeProcess::Stage1(_, val, _) | KeyExchangeProcess::Stage2(_, val, _) => {
                    *val = Some(peer_nat_info);
                }

                _ => {}
            }

            // since this is the server, we just need to route this to the target_cid
            let sess_mgr = inner!(session.session_manager);
            let signal_to = PeerSignal::Kex {
                peer_conn_type: conn,
                kex_payload: kep,
            };
            if sess_ratchet.get_cid() == conn.get_original_target_cid() {
                log::error!(target: "citadel", "Error (equivalent CIDs)");
                return Ok(PrimaryProcessorResult::Void);
            }

            let peer_cid = conn.get_original_target_cid();

            let res = sess_mgr.send_signal_to_peer_direct(peer_cid, move |peer_ratchet| {
                packet_crafter::peer_cmd::craft_peer_signal(
                    peer_ratchet,
                    signal_to,
                    ticket,
                    timestamp,
                    security_level,
                )
            });

            if let Err(err) = res {
                reply_to_sender_err(
                    err,
                    &sess_ratchet,
                    ticket,
                    timestamp,
                    security_level,
                    peer_cid,
                )
            } else {
                Ok(PrimaryProcessorResult::Void)
            }
        }

        PeerSignal::PostRegister {
            peer_conn_type,
            inviter_username: username,
            invitee_username: peer_username_opt,
            ticket_opt: _ticket_opt,
            invitee_response: peer_response,
        } => {
            // check to see if the client is connected, and if not, send to HypernodePeerLayer
            match peer_conn_type {
                PeerConnectionType::LocalGroupPeer {
                    session_cid: _session_cid,
                    peer_cid: target_cid,
                } => {
                    let session_cid = header.session_cid.get();
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour
                                                                            // if the peer response is some, then HyperLAN Client B responded
                    if let Some(peer_response) = peer_response {
                        // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
                        super::server::post_register::handle_response_phase_post_register(
                            peer_conn_type,
                            username,
                            peer_response,
                            ticket,
                            session_cid,
                            target_cid,
                            timestamp,
                            session,
                            &sess_ratchet,
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
                        let peer_conn_type = PeerConnectionType::LocalGroupPeer {
                            session_cid,
                            peer_cid: target_cid,
                        };

                        let mut peer_layer = session.hypernode_peer_layer.inner.write().await;
                        if let Some(ticket_new) =
                            peer_layer.check_simultaneous_register(session_cid, target_cid)
                        {
                            log::info!(target: "citadel", "Simultaneous register detected! Simulating session_cid={session_cid} sent an accept_register to target={target_cid}");
                            peer_layer.insert_mapped_ticket(session_cid, ticket_new, ticket);
                            drop(peer_layer);
                            // route signal to peer
                            let _ =
                                super::server::post_register::handle_response_phase_post_register(
                                    peer_conn_type,
                                    username.clone(),
                                    PeerResponse::Accept(Some(username)),
                                    ticket_new,
                                    session_cid,
                                    target_cid,
                                    timestamp,
                                    session,
                                    &sess_ratchet,
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
                            let peer_conn_type = PeerConnectionType::LocalGroupPeer {
                                session_cid: target_cid,
                                peer_cid: session_cid,
                            };
                            let cmd = PeerSignal::PostRegister {
                                peer_conn_type,
                                inviter_username: username.clone().unwrap_or_default(),
                                invitee_username: username,
                                ticket_opt: Some(ticket),
                                invitee_response: Some(accept),
                            };

                            let rebound_accept = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_ratchet,
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
                                PeerSignal::PostRegister {
                                    peer_conn_type,
                                    inviter_username: username,
                                    invitee_username: None,
                                    ticket_opt: Some(ticket),
                                    invitee_response: None,
                                },
                                TIMEOUT,
                                session_cid,
                                target_cid,
                                timestamp,
                                ticket,
                                &to_primary_stream,
                                &sess_mgr,
                                &sess_ratchet,
                                security_level,
                                &mut peer_layer,
                            )
                            .await
                        }
                    }
                }

                PeerConnectionType::ExternalGroupPeer {
                    session_cid: _session_cid,
                    interserver_cid: _icid,
                    peer_cid: _target_cid,
                } => {
                    log::warn!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::Deregister { peer_conn_type } => {
            // in deregistration, we send a Deregister signal to the peer (if connected)
            // then, delete the cid entry from the CNAC and save to the local FS
            match peer_conn_type {
                PeerConnectionType::LocalGroupPeer {
                    session_cid,
                    peer_cid: target_cid,
                } => {
                    let mut peer_layer_lock = session.hypernode_peer_layer.inner.write().await;
                    let account_manager = session.account_manager.clone();
                    let session_manager = session.session_manager.clone();

                    let mut register_event = false;

                    let dereg_result = if peer_layer_lock
                        .check_simultaneous_deregister(session_cid, target_cid)
                        .is_some()
                    {
                        // if the other peer is simultaneously deregistering, mark as Ok(())
                        log::info!(target: "citadel", "Simultaneous deregister detected");
                        Ok(())
                    } else {
                        register_event = true;
                        account_manager
                            .get_persistence_handler()
                            .deregister_p2p_as_server(session_cid, target_cid)
                            .await
                    };

                    match dereg_result {
                        Ok(_) => {
                            if register_event {
                                log::trace!(target: "citadel", "Registering dereg event");
                                peer_layer_lock
                                    .insert_tracked_posting(
                                        session_cid,
                                        Duration::from_secs(60 * 60),
                                        ticket,
                                        PeerSignal::DeregistrationSuccess { peer_conn_type },
                                        |_| {},
                                    )
                                    .await;
                            }
                            drop(peer_layer_lock);
                            let peer_alert_signal = PeerSignal::DeregistrationSuccess {
                                peer_conn_type: peer_conn_type.reverse(),
                            };
                            if !session_manager.send_signal_to_peer(
                                target_cid,
                                ticket,
                                peer_alert_signal,
                                timestamp,
                                security_level,
                            ) {
                                log::warn!(target: "citadel", "Unable to send packet to {target_cid} (maybe not connected)");
                            }

                            // now, send a success packet to the client
                            let success_cmd = PeerSignal::DeregistrationSuccess { peer_conn_type };
                            let rebound_packet = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_ratchet,
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
                            let error_signal = PeerSignal::SignalError {
                                ticket,
                                error: err.into_string(),
                                peer_connection_type: PeerConnectionType::LocalGroupPeer {
                                    session_cid,
                                    peer_cid: target_cid,
                                },
                            };
                            let error_packet = packet_crafter::peer_cmd::craft_peer_signal(
                                &sess_ratchet,
                                error_signal,
                                ticket,
                                timestamp,
                                security_level,
                            );
                            Ok(PrimaryProcessorResult::ReplyToSender(error_packet))
                        }
                    }
                }

                PeerConnectionType::ExternalGroupPeer {
                    session_cid: _session_cid,
                    interserver_cid: _icid,
                    peer_cid: _target_cid,
                } => {
                    log::warn!(target: "citadel", "HyperWAN functionality not yet enabled");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::PostConnect {
            peer_conn_type,
            ticket_opt: _ticket_opt,
            invitee_response: peer_response,
            session_security_settings: endpoint_security_level,
            udp_mode: udp_enabled,
            session_password,
        } => {
            match peer_conn_type {
                PeerConnectionType::LocalGroupPeer {
                    session_cid,
                    peer_cid: target_cid,
                } => {
                    // TODO: Change timeouts. Create a better timeout system, in general
                    const TIMEOUT: Duration = Duration::from_secs(60 * 60);
                    if let Some(peer_response) = peer_response {
                        super::server::post_connect::handle_response_phase_post_connect(
                            peer_conn_type,
                            ticket,
                            peer_response,
                            endpoint_security_level,
                            udp_enabled,
                            session_cid,
                            target_cid,
                            timestamp,
                            sess_ref,
                            &sess_ratchet,
                            security_level,
                        )
                        .await
                    } else {
                        // the signal is going to be routed from HyperLAN client A to HyperLAN client B (initiation phase)
                        let to_primary_stream = return_if_none!(session.to_primary_stream.clone());
                        let sess_mgr = session.session_manager.clone();
                        let peer_layer_arc = session.hypernode_peer_layer.inner.clone();
                        let mut peer_layer = peer_layer_arc.write().await;
                        if let Some(ticket_new) =
                            peer_layer.check_simultaneous_connect(session_cid, target_cid)
                        {
                            log::trace!(target: "citadel", "Simultaneous connect detected! Simulating session_cid={session_cid} sent an accept_connect to target={target_cid}");
                            log::trace!(target: "citadel", "Simultaneous connect: first_ticket: {ticket_new} | sender expected ticket: {ticket}");
                            peer_layer.insert_mapped_ticket(session_cid, ticket_new, ticket);
                            // NOTE: Packet will rebound to sender, then, sender will locally send
                            // packet to the peer who first attempted a connect request
                            drop(peer_layer);
                            let _ =
                                super::server::post_connect::handle_response_phase_post_connect(
                                    peer_conn_type,
                                    ticket_new,
                                    PeerResponse::Accept(None),
                                    endpoint_security_level,
                                    udp_enabled,
                                    session_cid,
                                    target_cid,
                                    timestamp,
                                    sess_ref,
                                    &sess_ratchet,
                                    security_level,
                                )
                                .await?;
                            Ok(PrimaryProcessorResult::Void)
                        } else {
                            // Drop the write lock before awaiting routing to avoid holding across await
                            drop(peer_layer);
                            route_signal_and_register_ticket_forwards_unlocked(
                                PeerSignal::PostConnect {
                                    peer_conn_type,
                                    ticket_opt: Some(ticket),
                                    invitee_response: None,
                                    session_security_settings: endpoint_security_level,
                                    udp_mode: udp_enabled,
                                    session_password,
                                },
                                TIMEOUT,
                                session_cid,
                                target_cid,
                                timestamp,
                                ticket,
                                &to_primary_stream,
                                &sess_mgr,
                                &sess_ratchet,
                                security_level,
                                &peer_layer_arc,
                            )
                            .await
                        }
                    }
                }

                PeerConnectionType::ExternalGroupPeer {
                    session_cid: _session_cid,
                    interserver_cid: _icid,
                    peer_cid: _target_cid,
                } => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::Disconnect {
            peer_conn_type,
            disconnect_response: resp,
        } => {
            match peer_conn_type {
                PeerConnectionType::LocalGroupPeer {
                    session_cid,
                    peer_cid: target_cid,
                } => {
                    let mut state_container = inner_mut_state!(session.state_container);
                    if state_container
                        .active_virtual_connections
                        .remove(&target_cid)
                        .is_some()
                    {
                        // note: this is w.r.t the server.
                        log::trace!(target: "citadel", "[Peer Vconn @ Server] will drop the virtual connection");
                        let resp = Some(resp.unwrap_or(PeerResponse::Disconnected(format!(
                            "Peer {session_cid} closed the virtual connection to {target_cid}"
                        ))));

                        let signal_to_peer = PeerSignal::Disconnect {
                            peer_conn_type: PeerConnectionType::LocalGroupPeer {
                                session_cid,
                                peer_cid: target_cid,
                            },
                            disconnect_response: resp,
                        };

                        // now, remove target CID's v_conn to `session_cid`
                        drop(state_container);
                        let _ = session.session_manager.disconnect_virtual_conn(
                            session_cid,
                            target_cid,
                            move |peer_ratchet| {
                                // send signal to peer
                                packet_crafter::peer_cmd::craft_peer_signal(
                                    peer_ratchet,
                                    signal_to_peer,
                                    ticket,
                                    timestamp,
                                    security_level,
                                )
                            },
                        );
                    }

                    // Regardless, always rebound a D/C signal
                    let rebound_signal = PeerSignal::Disconnect {
                        peer_conn_type: PeerConnectionType::LocalGroupPeer {
                            session_cid,
                            peer_cid: target_cid,
                        },
                        disconnect_response: Some(PeerResponse::Disconnected(
                            "Server has begun disconnection".to_string(),
                        )),
                    };

                    reply_to_sender(
                        rebound_signal,
                        &sess_ratchet,
                        ticket,
                        timestamp,
                        security_level,
                    )
                }

                _ => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::GetRegisteredPeers {
            peer_conn_type: hypernode_conn_type,
            response: _resp_opt,
            limit,
        } => {
            match hypernode_conn_type {
                ClientConnectionType::Server { session_cid: _ } => {
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
                        let peer_info = account_manager
                            .get_peer_info_from_cids(&registered_local_clients)
                            .await;
                        let mut all_peers = Vec::new();
                        for client in registered_local_clients.iter() {
                            if let Some(info) = peer_info.get(client) {
                                all_peers.push(info.clone());
                            }
                        }
                        PeerSignal::GetRegisteredPeers {
                            peer_conn_type: hypernode_conn_type,
                            response: Some(PeerResponse::RegisteredCids(all_peers, online_status)),
                            limit,
                        }
                    } else {
                        PeerSignal::GetRegisteredPeers {
                            peer_conn_type: hypernode_conn_type,
                            response: None,
                            limit,
                        }
                    };

                    log::trace!(target: "citadel", "[GetRegisteredPeers] Done getting list");
                    reply_to_sender(
                        rebound_signal,
                        &sess_ratchet,
                        ticket,
                        timestamp,
                        security_level,
                    )
                }

                ClientConnectionType::Extended {
                    session_cid: _,
                    interserver_cid: _,
                } => {
                    log::error!(target: "citadel", "HyperWAN functionality not implemented");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        PeerSignal::GetMutuals {
            v_conn_type: hypernode_conn_type,
            response: _resp_opt,
        } => match hypernode_conn_type {
            ClientConnectionType::Server { session_cid } => {
                let account_manager = session.account_manager.clone();
                let session_manager = session.session_manager.clone();

                log::trace!(target: "citadel", "[GetMutuals] Getting list");
                let rebound_signal = if let Some(mutuals) =
                    account_manager.get_hyperlan_peer_list(session_cid).await?
                {
                    let online_status = session_manager.check_online_status(&mutuals);
                    let peer_info = account_manager.get_peer_info_from_cids(&mutuals).await;
                    let mut all_peers = Vec::new();
                    for client in mutuals.iter() {
                        if let Some(info) = peer_info.get(client) {
                            all_peers.push(info.clone());
                        }
                    }
                    PeerSignal::GetMutuals {
                        v_conn_type: hypernode_conn_type,
                        response: Some(PeerResponse::RegisteredCids(all_peers, online_status)),
                    }
                } else {
                    PeerSignal::GetMutuals {
                        v_conn_type: hypernode_conn_type,
                        response: None,
                    }
                };

                log::trace!(target: "citadel", "[GetMutuals] Done getting list");
                reply_to_sender(
                    rebound_signal,
                    &sess_ratchet,
                    ticket,
                    timestamp,
                    security_level,
                )
            }

            ClientConnectionType::Extended {
                session_cid: _,
                interserver_cid: _,
            } => {
                log::error!(target: "citadel", "HyperWAN functionality not implemented");
                Ok(PrimaryProcessorResult::Void)
            }
        },

        PeerSignal::BroadcastConnected {
            session_cid: _cid,
            group_broadcast: _hypernode_conn_type,
        } => Ok(PrimaryProcessorResult::Void),

        PeerSignal::PostFileUploadRequest {
            peer_conn_type: _peer_conn_type,
            object_metadata: _file_metadata,
            ticket: _ticket,
        } => Ok(PrimaryProcessorResult::Void),

        PeerSignal::AcceptFileUploadRequest {
            peer_conn_type: _peer_conn_type,
            ticket: _ticket,
        } => Ok(PrimaryProcessorResult::Void),

        PeerSignal::SignalError {
            ticket,
            error,
            peer_connection_type,
        } => {
            // in this case, we delegate the error to the higher-level kernel to determine what to do
            let signal = PeerSignal::SignalError {
                ticket,
                error,
                peer_connection_type,
            };
            session
                .kernel_tx
                .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                    event: signal.clone(),
                    ticket,
                    session_cid: sess_ratchet.get_cid(),
                }))?;

            let peer_cid = peer_connection_type.get_original_target_cid();
            // If this was a simultaneous connect, we need to remap the ticket
            let mut peer_layer = session.hypernode_peer_layer.inner.write().await;
            let ticket = peer_layer
                .take_mapped_ticket(peer_cid, ticket)
                .unwrap_or(ticket);
            drop(peer_layer);

            let res = inner!(session.session_manager).send_signal_to_peer_direct(
                peer_cid,
                move |peer_ratchet| {
                    packet_crafter::peer_cmd::craft_peer_signal(
                        peer_ratchet,
                        signal,
                        ticket,
                        timestamp,
                        security_level,
                    )
                },
            );

            if let Err(err) = res {
                reply_to_sender_err(
                    err,
                    &sess_ratchet,
                    ticket,
                    timestamp,
                    security_level,
                    peer_cid,
                )
            } else {
                Ok(PrimaryProcessorResult::Void)
            }
        }

        PeerSignal::SignalReceived { ticket } => {
            session
                .kernel_tx
                .unbounded_send(NodeResult::PeerEvent(PeerEvent {
                    event: signal,
                    ticket,
                    session_cid: sess_ratchet.get_cid(),
                }))?;
            Ok(PrimaryProcessorResult::Void)
        }

        PeerSignal::DeregistrationSuccess { .. } => Ok(PrimaryProcessorResult::Void),

        PeerSignal::DisconnectUDP { peer_conn_type } => {
            // close this UDP channel
            inner_mut_state!(session.state_container)
                .remove_udp_channel(peer_conn_type.get_original_target_cid());
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

#[inline]
/// This just makes the repeated operation above cleaner. By itself does not send anything; must return the result of this closure directly
fn reply_to_sender<R: Ratchet>(
    signal: PeerSignal,
    ratchet: &R,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        ratchet,
        signal,
        ticket,
        timestamp,
        security_level,
    );
    Ok(PrimaryProcessorResult::ReplyToSender(packet))
}

fn reply_to_sender_err<E: ToString, R: Ratchet>(
    err: E,
    ratchet: &R,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
    peer_cid: u64,
) -> Result<PrimaryProcessorResult, NetworkError> {
    Ok(PrimaryProcessorResult::ReplyToSender(
        construct_error_signal(err, ratchet, ticket, timestamp, security_level, peer_cid),
    ))
}

fn construct_error_signal<E: ToString, R: Ratchet>(
    err: E,
    ratchet: &R,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
    peer_cid: u64,
) -> BytesMut {
    let err_signal = PeerSignal::SignalError {
        ticket,
        error: err.to_string(),
        peer_connection_type: PeerConnectionType::LocalGroupPeer {
            session_cid: ratchet.get_cid(),
            peer_cid,
        },
    };
    packet_crafter::peer_cmd::craft_peer_signal(
        ratchet,
        err_signal,
        ticket,
        timestamp,
        security_level,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn route_signal_and_register_ticket_forwards<R: Ratchet>(
    signal: PeerSignal,
    timeout: Duration,
    session_cid: u64,
    target_cid: u64,
    timestamp: i64,
    ticket: Ticket,
    to_primary_stream: &OutboundPrimaryStreamSender,
    sess_mgr: &CitadelSessionManager<R>,
    sess_ratchet: &R,
    security_level: SecurityLevel,
    peer_layer: &mut CitadelNodePeerLayerInner<R>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let sess_ratchet_2 = sess_ratchet.clone();
    let to_primary_stream = to_primary_stream.clone();

    // Give the target_cid 10 seconds to respond
    let res = sess_mgr.route_signal_primary(peer_layer, session_cid, target_cid, ticket, signal.clone(), move |peer_ratchet| {
        packet_crafter::peer_cmd::craft_peer_signal(peer_ratchet, signal.clone(), ticket, timestamp, security_level)
    }, timeout, move |stale_signal| {
        // on timeout, run this
        // TODO: Use latest ratchet, otherwise, may expire
        log::warn!(target: "citadel", "Running timeout closure. Sending error message to {session_cid}");
        let error_packet = packet_crafter::peer_cmd::craft_peer_signal(&sess_ratchet_2, stale_signal, ticket, timestamp, security_level);
        let _ = to_primary_stream.unbounded_send(error_packet);
    }).await;

    // Then, we tell the session_cid's node that we have handled the message. However, the peer has yet to respond
    if let Err(err) = res {
        reply_to_sender_err(
            err,
            sess_ratchet,
            ticket,
            timestamp,
            security_level,
            target_cid,
        )
    } else {
        Ok(PrimaryProcessorResult::Void)
    }
}

// @human-review: Introduced unlocked variant to avoid holding peer_layer write lock across await. Semantics unchanged; routing still occurs with a short-lived write lock.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn route_signal_and_register_ticket_forwards_unlocked<R: Ratchet>(
    signal: PeerSignal,
    timeout: Duration,
    session_cid: u64,
    target_cid: u64,
    timestamp: i64,
    ticket: Ticket,
    to_primary_stream: &OutboundPrimaryStreamSender,
    sess_mgr: &CitadelSessionManager<R>,
    sess_ratchet: &R,
    security_level: SecurityLevel,
    peer_layer_arc: &std::sync::Arc<citadel_io::tokio::sync::RwLock<CitadelNodePeerLayerInner<R>>>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let sess_ratchet_2 = sess_ratchet.clone();
    let to_primary_stream = to_primary_stream.clone();

    // Acquire write lock only during the routing operation
    let mut peer_layer = peer_layer_arc.write().await;

    let res = sess_mgr
        .route_signal_primary(
            &mut *peer_layer,
            session_cid,
            target_cid,
            ticket,
            signal.clone(),
            move |peer_ratchet| {
                packet_crafter::peer_cmd::craft_peer_signal(
                    peer_ratchet,
                    signal.clone(),
                    ticket,
                    timestamp,
                    security_level,
                )
            },
            timeout,
            move |stale_signal| {
                log::warn!(target: "citadel", "Running timeout closure. Sending error message to {session_cid}");
                let error_packet = packet_crafter::peer_cmd::craft_peer_signal(
                    &sess_ratchet_2,
                    stale_signal,
                    ticket,
                    timestamp,
                    security_level,
                );
                let _ = to_primary_stream.unbounded_send(error_packet);
            },
        )
        .await;

    drop(peer_layer);

    if let Err(err) = res {
        reply_to_sender_err(
            err,
            sess_ratchet,
            ticket,
            timestamp,
            security_level,
            target_cid,
        )
    } else {
        Ok(PrimaryProcessorResult::Void)
    }
}

// returns (true, status) if the process was a success, or (false, success) otherwise
#[allow(clippy::too_many_arguments)]
pub(crate) async fn route_signal_response<R: Ratchet>(
    signal: PeerSignal,
    session_cid: u64,
    target_cid: u64,
    timestamp: i64,
    ticket: Ticket,
    session: CitadelSession<R>,
    sess_ratchet: &R,
    on_route_finished: impl FnOnce(&CitadelSession<R>, &CitadelSession<R>, PeerSignal),
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    trace!(target: "citadel", "Routing signal {signal:?} | impl: {session_cid} | target: {target_cid}");
    let sess_ref = &session;

    let res = session
        .session_manager
        .route_signal_response_primary(
            session_cid,
            target_cid,
            ticket,
            sess_ref,
            move |peer_ratchet| {
                packet_crafter::peer_cmd::craft_peer_signal(
                    peer_ratchet,
                    signal,
                    ticket,
                    timestamp,
                    security_level,
                )
            },
            move |peer_sess, original_posting| {
                // send a notification that the server forwarded the signal
                let received_signal = PeerSignal::SignalReceived { ticket };
                let ret = reply_to_sender(
                    received_signal,
                    sess_ratchet,
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
            log::warn!(target: "citadel", "Unable to route signal! {err:?}");
            reply_to_sender_err(
                err,
                sess_ratchet,
                ticket,
                timestamp,
                security_level,
                target_cid,
            )
        }
    }
}
