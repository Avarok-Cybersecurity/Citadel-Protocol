//! # Raw Primary Packet Processor
//!
//! Low-level packet processing implementation for primary data packets in the
//! Citadel Protocol, handling raw packet operations and transformations.
//!
//! ## Features
//!
//! - **Packet Operations**:
//!   - Raw packet parsing
//!   - Header processing
//!   - Payload handling
//!   - Packet validation
//!
//! - **Data Management**:
//!   - Zero-copy processing
//!   - Buffer management
//!   - Memory safety
//!   - Efficient allocation
//!
//! - **Security**:
//!   - Header integrity
//!   - Payload verification
//!   - Length validation
//!   - Type checking
//!
//! ## Important Notes
//!
//! - Implements memory-safe operations
//! - Handles packet boundaries correctly
//! - Validates packet structure
//! - Ensures data integrity
//!
//! ## Related Components
//!
//! - [`primary_group_packet`]: Group packet processing
//! - [`peer_cmd_packet`]: Peer command packets
//! - [`file_packet`]: File transfer packets
//! - [`session_manager`]: Session management

use crate::proto::packet_processor::peer::peer_cmd_packet;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;

use super::includes::*;
use crate::error::NetworkError;

/// For primary-port packet types. NOT for wave ports
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(session_cid=this_session_cid, is_server=session.is_server, packet_len=input_packet.len())
))]
pub async fn process_raw_packet<R: Ratchet>(
    this_session_cid: Option<u64>,
    session: &CitadelSession<R>,
    remote_peer: SocketAddr,
    local_primary_port: u16,
    input_packet: BytesMut, // Renamed to avoid conflict
) -> Result<PrimaryProcessorResult, NetworkError> {
    // It's important that HdpPacket construction and initial parsing are quick and don't block.
    // Assuming HdpPacket::new_recv and .parse() are efficient.
    let temp_hdp_packet = HdpPacket::new_recv(input_packet.clone(), remote_peer, local_primary_port);
    let parsed_header = match temp_hdp_packet.parse() {
        Some(h) => h.0, // Get the Header directly
        None => {
            log::warn!(target: "citadel", "Unable to parse packet {:?} | Len: {}", input_packet.as_bytes(), input_packet.len());
            return Ok(PrimaryProcessorResult::Void);
        }
    };

    log::trace!(target: "citadel", "RECV Raw packet: {:?}", &parsed_header);
    
    let target_cid = parsed_header.target_cid.get();
    let cmd_primary = parsed_header.cmd_primary;
    let cmd_aux = parsed_header.cmd_aux;
    let header_entropy_bank_vers = parsed_header.entropy_bank_version.get();
    let header_session_cid = parsed_header.session_cid.get();

    // Clone necessary data for spawn_blocking
    let session_clone_for_check_proxy = session.clone();
    // HdpPacket should be Send. BytesMut is Send.
    let packet_for_check_proxy = input_packet; 

    let (packet_after_proxy_check_opt, endpoint_cid_info_from_blocking) = 
        tokio::task::spawn_blocking(move || {
            let mut endpoint_cid_info_blocking: Option<(u64,u64)> = None;
            // Reconstruct HdpPacket inside blocking task if it's not Send, or if original packet is modified by parse()
            // For now, assuming packet_for_check_proxy (BytesMut) is sufficient to reconstruct or HdpPacket is Send
            let hdp_packet_for_check_proxy = HdpPacket::new_recv(packet_for_check_proxy, remote_peer, local_primary_port);

            let result_packet = check_proxy(
                this_session_cid,
                cmd_primary, // Use pre-parsed cmd_primary
                cmd_aux,     // Use pre-parsed cmd_aux
                header_session_cid, // Use pre-parsed header_session_cid
                target_cid,  // Use pre-parsed target_cid
                &session_clone_for_check_proxy,
                &mut endpoint_cid_info_blocking,
                ReceivePortType::OrderedReliable,
                hdp_packet_for_check_proxy, // Pass the HdpPacket
            );
            (result_packet, endpoint_cid_info_blocking)
        }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for check_proxy failed: {}", e)))?;

    if let Some(packet_to_process) = packet_after_proxy_check_opt {
        let final_endpoint_cid_info = endpoint_cid_info_from_blocking;

        match cmd_primary {
            packet_flags::cmd::primary::DO_REGISTER => {
                super::register_packet::process_register(session, packet_to_process, remote_peer).await
            }

            packet_flags::cmd::primary::DO_CONNECT => {
                super::connect_packet::process_connect(session, packet_to_process, header_entropy_bank_vers).await
            }

            packet_flags::cmd::primary::KEEP_ALIVE => {
                super::keep_alive_packet::process_keep_alive(session, packet_to_process, header_entropy_bank_vers).await
            }

            packet_flags::cmd::primary::GROUP_PACKET => {
                // This was originally synchronous. Wrap in spawn_blocking.
                let session_clone_group = session.clone();
                tokio::task::spawn_blocking(move || {
                    super::primary_group_packet::process_primary_packet(
                        &session_clone_group,
                        cmd_aux,
                        packet_to_process,
                        final_endpoint_cid_info,
                    )
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for group_packet failed: {}", e)))?
            }

            packet_flags::cmd::primary::DO_DISCONNECT => {
                super::disconnect_packet::process_disconnect(session, packet_to_process, header_entropy_bank_vers).await
            }

            packet_flags::cmd::primary::DO_DEREGISTER => {
                super::deregister_packet::process_deregister(session, packet_to_process, header_entropy_bank_vers).await
            }

            packet_flags::cmd::primary::DO_PRE_CONNECT => {
                super::preconnect_packet::process_preconnect(session, packet_to_process, header_entropy_bank_vers).await
            }

            packet_flags::cmd::primary::PEER_CMD => {
                peer_cmd_packet::process_peer_cmd(
                    session,
                    cmd_aux,
                    packet_to_process,
                    header_entropy_bank_vers,
                    final_endpoint_cid_info,
                ).await
            }

            packet_flags::cmd::primary::FILE => {
                // This was originally synchronous. Wrap in spawn_blocking.
                let session_clone_file = session.clone();
                tokio::task::spawn_blocking(move || {
                    super::file_packet::process_file_packet(&session_clone_file, packet_to_process, final_endpoint_cid_info)
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for file_packet failed: {}", e)))?
            }

            packet_flags::cmd::primary::HOLE_PUNCH => {
                // This was originally synchronous. Wrap in spawn_blocking.
                let session_clone_hole_punch = session.clone();
                tokio::task::spawn_blocking(move || {
                    super::hole_punch::process_hole_punch(
                        &session_clone_hole_punch,
                        packet_to_process,
                        header_entropy_bank_vers,
                        final_endpoint_cid_info,
                    )
                }).await.map_err(|e| NetworkError::Generic(format!("spawn_blocking for hole_punch failed: {}", e)))?
            }

            _ => {
                warn!(target: "citadel", "The primary port received an invalid packet command. Dropping");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    } else {
        // Packet was proxied
        Ok(PrimaryProcessorResult::Void)
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ReceivePortType {
    OrderedReliable,
    UnorderedUnreliable,
}

/// Checks if the packet should be proxied or not.
///
/// If the packet should be proxied, it will be sent to the target CID and the function will return `None`.
/// If the packet should not be proxied, it will be returned as is.
///
/// # Parameters
///
/// - `this_session_cid`: The implicated CID of the current session.
/// - `cmd_primary`: The primary command of the packet.
/// - `cmd_aux`: The auxiliary command of the packet.
/// - `header_session_cid`: The session CID of the packet.
/// - `target_cid`: The target CID of the packet.
/// - `session`: The current session.
/// - `endpoint_cid_info`: The endpoint CID information.
/// - `recv_port_type`: The type of the receive port.
/// - `packet`: The packet to be checked.
///
/// # Returns
///
/// - `Some(packet)`: The packet if it should not be proxied.
/// - `None`: If the packet should be proxied.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(crate) fn check_proxy<R: Ratchet>(
    this_session_cid: Option<u64>,
    cmd_primary: u8,
    cmd_aux: u8,
    header_session_cid: u64,
    target_cid: u64,
    session: &CitadelSession<R>,
    endpoint_cid_info: &mut Option<(u64, u64)>,
    recv_port_type: ReceivePortType,
    packet: HdpPacket,
) -> Option<HdpPacket> {
    if target_cid != 0 {
        // since target cid is not zero, there are two possibilities:
        // either [A] we are at the hLAN server, in which case the this_session_cid != target_cid
        // or, [B] we are at the destination, in which case session_cid == target_cid. If this is true, do normal processing
        // NOTE: When proxying DO NOT change the original implicated_CID in the header.
        // [*] in the case of proxying, it should only be done after a connection is well established
        // This would imply that the implicated cid is established in the HdpSession. As such, if the implicated CID is None,
        // then simply let normal logic below continue
        if let Some(this_session_cid_val) = this_session_cid {
            // this implies there is at least a connection between hLAN client and hLAN server, but we don't know which is which
            if this_session_cid_val != target_cid {
                log::trace!(target: "citadel", "Proxying {}:{} packet from {} to {}", cmd_primary, cmd_aux, this_session_cid_val, target_cid);
                // Proxy will only occur if there exists a virtual connection, in which case, we get the TcpSender (since these are primary packets)

                let mut state_container = inner_mut_state!(session.state_container);
                state_container.meta_expiry_state.on_event_confirmation();

                if let Some(peer_vconn) =
                    state_container.active_virtual_connections.get(&target_cid)
                {
                    // Ensure that any p2p conn proxied packets (i.e., TURNed packets) can continue to traverse until any full disconnections occur
                    peer_vconn
                        .last_delivered_message_timestamp
                        .set(Some(Instant::now()));
                    // into_packet is a cheap operation the freezes the internal packet; we attain zero-copy when proxying here
                    match recv_port_type {
                        ReceivePortType::OrderedReliable => {
                            #[cfg(all(
                                feature = "localhost-testing",
                                feature = "localhost-testing-assert-no-proxy"
                            ))]
                            {
                                if cmd_primary == packet_flags::cmd::primary::GROUP_PACKET
                                    && cmd_aux == packet_flags::cmd::aux::group::GROUP_HEADER
                                {
                                    log::error!(target: "citadel", "***Did not expect packet to be proxied via feature flag*** | local is server: {}", session.is_server);
                                    std::process::exit(1)
                                }
                            }

                            if let Err(_err) = peer_vconn
                                .sender
                                .as_ref()
                                .unwrap()
                                .1
                                .unbounded_send(packet.into_packet())
                            {
                                log::warn!(target: "citadel", "Proxy TrySendError to {}", target_cid);
                            }
                        }

                        ReceivePortType::UnorderedUnreliable => {
                            if let Some(udp_sender) = peer_vconn.sender.as_ref().unwrap().0.as_ref()
                            {
                                if let Err(_err) = udp_sender.unbounded_send(packet.into_packet()) {
                                    log::error!(target: "citadel", "Proxy TrySendError to {}", target_cid);
                                }
                            } else {
                                log::error!(target: "citadel", "UDP sender not yet loaded (proxy)");
                            }
                        }
                    }
                } else {
                    log::warn!(target: "citadel", "Unable to proxy; virtual connection to {} is not alive", target_cid);
                }

                return None;
            } else {
                // since session_cid == target_cid, and target_cid != 0, we are at the destination
                // and need to use the endpoint crypto in order to process the packets
                *endpoint_cid_info = Some((header_session_cid, target_cid))
            }
        }
    }

    Some(packet)
}
