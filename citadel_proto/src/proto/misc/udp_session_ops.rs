//! UDP Session Operations Abstraction
//!
//! Provides standalone functions for UDP session lifecycle management with
//! platform-specific dispatch via `cfg`. Native targets perform full UDP I/O;
//! WASM targets provide no-op stubs.
//!
//! All cfg-gates for UDP session operations are concentrated in this module so
//! the protocol layer (session, packet processors) remains platform-agnostic.

use crate::error::NetworkError;
use crate::proto::misc::udp_internal_interface::UdpSplittableTypes;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualTargetType;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::ProtocolIO;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;

/// Spawn the UDP socket loader, which sets up the UDP subsystem for a session.
///
/// On native: spawns an async task that waits for TCP readiness, splits the UDP
/// connection, inserts channels into the state container, and runs the
/// listener + sender loop.
///
/// On WASM: no-op (UDP handled via WebRTC DataChannels, not raw sockets).
pub(crate) fn spawn_udp_socket_loader<R: Ratchet, T: ProtocolIO>(
    session: CitadelSession<R, T>,
    v_target: VirtualTargetType,
    udp_conn: UdpSplittableTypes,
    addr: TargettedSocketAddr,
    ticket: Ticket,
    tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
) {
    #[cfg(not(target_family = "wasm"))]
    {
        spawn_udp_socket_loader_native(session, v_target, udp_conn, addr, ticket, tcp_conn_awaiter);
    }

    #[cfg(target_family = "wasm")]
    {
        let _ = (session, v_target, udp_conn, addr, ticket, tcp_conn_awaiter);
    }
}

#[cfg(not(target_family = "wasm"))]
fn spawn_udp_socket_loader_native<R: Ratchet, T: ProtocolIO>(
    this: CitadelSession<R, T>,
    v_target: VirtualTargetType,
    udp_conn: UdpSplittableTypes,
    addr: TargettedSocketAddr,
    ticket: Ticket,
    tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
) {
    use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
    use crate::proto::outbound_sender::{unbounded, OutboundUdpSender};
    use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
    use crate::proto::state_container::VirtualConnectionType;

    let this_weak = this.as_weak();
    std::mem::drop(this);
    let task = async move {
        let (listener, udp_sender_future, stopper_rx) = {
            let this = CitadelSession::upgrade_weak(&this_weak)
                .ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

            let sess = this;

            // we supply the natted ip since it is where we expect to receive packets
            // whether local is server or not, we should expect to receive packets from natted
            let hole_punched_socket = addr.receive_address;
            let hole_punched_addr_ip = hole_punched_socket.ip();

            let local_bind_addr = udp_conn.local_addr().unwrap();
            let needs_manual_ka = udp_conn.needs_manual_ka();

            let (outbound_sender_tx, outbound_sender_rx) = unbounded();
            let udp_sender = OutboundUdpSender::new(
                outbound_sender_tx,
                local_bind_addr,
                hole_punched_socket,
                needs_manual_ka,
            );
            let (stopper_tx, stopper_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

            let is_server = sess.is_server;
            std::mem::drop(sess);
            if let Some(tcp_conn_awaiter) = tcp_conn_awaiter {
                log::trace!(target: "citadel", "Awaiting tcp conn to finish before creating UDP subsystem ... is_server={is_server}");
                tcp_conn_awaiter
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
            }

            let sess = CitadelSession::upgrade_weak(&this_weak)
                .ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

            let accessor = match v_target {
                VirtualConnectionType::LocalGroupServer { session_cid: _ } => {
                    let mut state_container = inner_mut_state!(sess.state_container);
                    state_container.udp_primary_outbound_tx = Some(udp_sender.clone());
                    log::trace!(target: "citadel", "C2S UDP subroutine inserting UDP channel ... (is_server={is_server})");
                    if let Some(channel) = state_container.insert_udp_channel(
                        C2S_IDENTITY_CID,
                        v_target,
                        ticket,
                        udp_sender,
                        stopper_tx,
                    ) {
                        log::trace!(target: "citadel", "C2S UDP subroutine created udp channel ... (is_server={is_server})");
                        if let Some(sender) = state_container
                            .pre_connect_state
                            .udp_channel_oneshot_tx
                            .tx
                            .take()
                        {
                            //TODO: await before sending Channel to c2s or p2p
                            log::trace!(target: "citadel", "C2S UDP subroutine sending channel to local user ... (is_server={is_server})");
                            sender.send(channel).map_err(|_| {
                                NetworkError::InternalError("Unable to send UdpChannel through")
                            })?;
                            EndpointCryptoAccessor::C2S(sess.state_container.clone())
                        } else {
                            log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had no UDP sender");
                            return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"));
                        }
                    } else {
                        log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                        return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."));
                    }
                }

                VirtualConnectionType::LocalGroupPeer {
                    session_cid: _session_cid,
                    peer_cid: target_cid,
                } => {
                    let mut state_container = inner_mut_state!(sess.state_container);
                    if let Some(channel) = state_container
                        .insert_udp_channel(target_cid, v_target, ticket, udp_sender, stopper_tx)
                    {
                        if let Some(kem_state) =
                            state_container.peer_kem_states.get_mut(&target_cid)
                        {
                            // Below will fail if UDP mode is off, as desired
                            if let Some(sender) = kem_state.udp_channel_sender.tx.take() {
                                // below will fail if the user drops the receiver at the kernel-level
                                sender.send(channel).map_err(|_| {
                                    NetworkError::InternalError("Unable to send UdpChannel through")
                                })?;
                                EndpointCryptoAccessor::P2P(
                                    target_cid,
                                    sess.state_container.clone(),
                                )
                            } else {
                                log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had no UDP sender");
                                return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"));
                            }
                        } else {
                            log::error!(target: "citadel", "Tried loading the peer kem state, but was absent");
                            return Err(NetworkError::InternalError(
                                "Tried loading the peer kem state, but was absent",
                            ));
                        }
                    } else {
                        log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                        return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."));
                    }
                }

                _ => {
                    return Err(NetworkError::InternalError("Invalid virtual target"));
                }
            };

            // Unlike TCP, we will not use [LengthDelimitedCodec] because there is no guarantee that packets
            // will arrive in order
            let (writer, reader) = udp_conn.split();

            let listener = listen_udp_port(
                sess,
                hole_punched_addr_ip,
                local_bind_addr.port(),
                reader,
                accessor.clone(),
            );

            log::trace!(target: "citadel", "Server established UDP Port {local_bind_addr}");

            let udp_sender_future = udp_outbound_sender(outbound_sender_rx, addr, writer, accessor);
            (listener, udp_sender_future, stopper_rx)
        };

        log::trace!(target: "citadel", "[Q-UDP] Initiated UDP subsystem...");

        let stopper = async move {
            let _ = stopper_rx.await;
        };

        citadel_io::tokio::select! {
            res0 = listener => res0,
            res1 = udp_sender_future => res1,
            _ = stopper => Ok(())
        }
    };

    let wrapped_task = async move {
        if let Err(err) = task.await {
            log::error!(target: "citadel", "UDP task failed: {err:?}");
        } else {
            log::trace!(target: "citadel", "UDP ended without error");
        }
    };

    spawn!(wrapped_task);
}

#[cfg(not(target_family = "wasm"))]
async fn listen_udp_port<
    R: Ratchet,
    T: ProtocolIO,
    S: crate::proto::misc::udp_internal_interface::UdpStream,
>(
    this: CitadelSession<R, T>,
    _hole_punched_addr_ip: std::net::IpAddr,
    local_port: u16,
    mut stream: S,
    peer_session_accessor: crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor<R>,
) -> Result<(), NetworkError> {
    use crate::proto::packet::HdpPacket;
    use futures::StreamExt;

    while let Some(res) = stream.next().await {
        match res {
            Ok((packet, remote_peer)) => {
                log::trace!(target: "citadel", "Packet received on port {} has {} bytes (src: {:?})", local_port, packet.len(), &remote_peer);
                let packet = HdpPacket::new_recv(packet, remote_peer, local_port);
                this.process_inbound_packet_udp(packet, &peer_session_accessor)?;
            }

            Err(err) => {
                log::warn!(target: "citadel", "UDP Stream error: {err:#?}");
                break;
            }
        }
    }

    log::trace!(target: "citadel", "Ending UDP Port listener on {local_port}");

    Ok(())
}

#[cfg(not(target_family = "wasm"))]
async fn udp_outbound_sender<R: Ratchet, S: futures::SinkExt<bytes::Bytes> + Unpin>(
    receiver: crate::proto::outbound_sender::UnboundedReceiver<(u8, bytes::BytesMut)>,
    hole_punched_addr: TargettedSocketAddr,
    mut sink: S,
    peer_session_accessor: crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor<R>,
) -> Result<(), NetworkError> {
    use citadel_types::crypto::SecurityLevel;
    use futures::StreamExt;

    let mut receiver = citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(receiver);
    let target_cid = peer_session_accessor.get_target_cid();

    while let Some((cmd_aux, packet)) = receiver.next().await {
        let send_addr = hole_punched_addr.send_address;
        let packet = peer_session_accessor.borrow_hr(None, |hr, _| {
            crate::proto::packet_crafter::udp::craft_udp_packet(
                hr,
                cmd_aux,
                packet,
                target_cid,
                SecurityLevel::Standard,
            )
        })?;
        log::trace!(target: "citadel", "About to send packet w/len {} | Dest: {:?}", packet.len(), &send_addr);
        sink.send(packet.freeze()).await.map_err(|_| {
            NetworkError::InternalError("UDP sink unable to receive outbound requests")
        })?;
    }

    log::trace!(target: "citadel", "Outbound wave sender ending");

    Ok(())
}
