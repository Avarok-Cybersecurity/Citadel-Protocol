//! NAT Traversal Abstraction
//!
//! Provides standalone functions that abstract NAT traversal operations with
//! platform-specific dispatch via `cfg`. Native targets perform real hole
//! punching; WASM targets return stubs (or will use WebRTC DataChannels in
//! future phases).
//!
//! All cfg-gates for NAT traversal are concentrated in this module so the
//! protocol layer (packet processors, session, etc.) remains platform-agnostic.

use crate::error::NetworkError;
use crate::proto::misc::udp_internal_interface::UdpSplittableTypes;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_wire::exports::Connection;
use citadel_wire::nat_identification::NatType;
use netbeam::sync::RelativeNodeType;
use std::net::SocketAddr;

/// Create a UDP channel from an existing QUIC connection.
/// On WASM, returns `None` (QUIC not yet available).
pub(crate) fn quic_udp_channel(
    conn: Connection,
    local_addr: SocketAddr,
) -> Option<UdpSplittableTypes> {
    #[cfg(not(target_family = "wasm"))]
    {
        use crate::proto::misc::udp_internal_interface::QuicUdpSocketConnector;
        log::trace!(target: "citadel", "Will use QUIC UDP for UDP transmission");
        Some(UdpSplittableTypes::Quic(QuicUdpSocketConnector::new(
            conn, local_addr,
        )))
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = (conn, local_addr);
        None
    }
}

/// Perform C2S UDP hole punch via `NetworkEndpoint` + encrypted hole punch.
/// Returns the resulting UDP interface, or `None` if unavailable/failed.
/// On WASM, always returns `Ok(None)`.
pub(crate) async fn c2s_hole_punch<R: Ratchet>(
    stream: ReliableOrderedCompatStream<R>,
    ratchet: R,
    security_level: SecurityLevel,
    target_cid: u64,
    stun_servers: Option<Vec<String>>,
    node_type: RelativeNodeType,
) -> Result<Option<UdpSplittableTypes>, NetworkError> {
    #[cfg(not(target_family = "wasm"))]
    {
        use crate::proto::misc::udp_internal_interface::RawUdpSocketConnector;
        use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
        use netbeam::sync::network_endpoint::NetworkEndpoint;

        let endpoint = NetworkEndpoint::register(node_type, stream)
            .await
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        log::trace!(target: "citadel", "{node_type:?} created for C2S hole punch");

        let config =
            generate_hole_punch_crypt_container(ratchet, security_level, target_cid, stun_servers);

        match endpoint.begin_udp_hole_punch(config).await {
            Ok(socket) => {
                log::trace!(target: "citadel", "{node_type:?} finished NAT traversal");
                let send_addr = socket.addr.send_address;
                Ok(Some(UdpSplittableTypes::Raw(RawUdpSocketConnector::new(
                    socket.into_socket(),
                    send_addr,
                ))))
            }
            Err(err) => {
                log::warn!(target: "citadel", "Hole punch attempt failed: {err}");
                Ok(None)
            }
        }
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = (
            stream,
            ratchet,
            security_level,
            target_cid,
            stun_servers,
            node_type,
        );
        Ok(None)
    }
}

/// Orchestrate P2P hole punch: register endpoint, hole punch, establish
/// QUIC connection, and send `channel_signal` to kernel.
/// On failure (or on WASM), sends `channel_signal` as TCP-only fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn p2p_hole_punch<R: Ratchet, T: citadel_io::ProtocolIO>(
    session: crate::proto::session::CitadelSession<R, T>,
    peer_connection_type: crate::proto::peer::peer_layer::PeerConnectionType,
    ticket: crate::proto::remote::Ticket,
    peer_nat_info: crate::proto::peer::peer_crypt::PeerNatInfo,
    channel_signal: crate::proto::node_result::NodeResult<R>,
    hole_punch_compat_stream: ReliableOrderedCompatStream<R>,
    endpoint_ratchet: R,
    peer_cid: u64,
    sync_instant: citadel_io::time::Instant,
    node_type: RelativeNodeType,
    udp_mode: citadel_types::proto::UdpMode,
    session_security_settings: citadel_types::proto::SessionSecuritySettings,
    cancel_rx: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
) -> Result<(), NetworkError> {
    #[cfg(not(target_family = "wasm"))]
    {
        use crate::proto::peer::p2p_conn_handler;
        use netbeam::sync::network_endpoint::NetworkEndpoint;
        use std::time::Duration;

        let stun_servers = session.stun_servers.clone();
        let session_cid = session.session_cid.clone();
        let kernel_tx = session.kernel_tx.clone();
        let session_alive = session.alive_tracker();
        let client_config = session.client_config.clone();

        const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
        match citadel_io::time::timeout(
            REGISTER_TIMEOUT,
            NetworkEndpoint::register(node_type, hole_punch_compat_stream),
        )
        .await
        {
            Ok(Ok(app)) => {
                let encrypted_config_container = generate_hole_punch_crypt_container(
                    endpoint_ratchet,
                    SecurityLevel::Standard,
                    peer_cid,
                    stun_servers,
                );
                let _ = p2p_conn_handler::attempt_simultaneous_hole_punch(
                    peer_connection_type,
                    ticket,
                    session,
                    peer_nat_info,
                    session_cid,
                    kernel_tx,
                    channel_signal,
                    sync_instant,
                    app,
                    encrypted_config_container,
                    client_config,
                    udp_mode,
                    session_security_settings,
                    cancel_rx,
                    session_alive,
                )
                .await;
                Ok(())
            }
            Ok(Err(err)) => {
                log::warn!(target: "citadel", "NetworkEndpoint register failed: {err}, sending TCP-only channel");
                session.send_to_kernel(channel_signal)?;
                Ok(())
            }
            Err(_) => {
                log::warn!(target: "citadel", "NetworkEndpoint register timed out after {REGISTER_TIMEOUT:?}, sending TCP-only channel");
                session.send_to_kernel(channel_signal)?;
                Ok(())
            }
        }
    }
    #[cfg(target_family = "wasm")]
    {
        // On WASM, skip hole punch and send TCP-only channel signal
        let _ = (
            peer_connection_type,
            ticket,
            peer_nat_info,
            hole_punch_compat_stream,
            endpoint_ratchet,
            peer_cid,
            sync_instant,
            node_type,
            udp_mode,
            session_security_settings,
            cancel_rx,
        );
        session.send_to_kernel(channel_signal)?;
        Ok(())
    }
}

/// Identify local NAT type via STUN servers.
/// On WASM, returns `NatType::offline()`.
pub(crate) async fn identify_nat_type(
    stun_servers: Option<Vec<String>>,
) -> std::io::Result<NatType> {
    #[cfg(not(target_family = "wasm"))]
    {
        NatType::identify(stun_servers)
            .await
            .map_err(|e| std::io::Error::other(format!("NAT identification failed: {e}")))
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = stun_servers;
        Ok(NatType::offline())
    }
}

/// Generate a `HolePunchConfigContainer` with encryption/decryption closures
/// using the given ratchet. Only available on native targets.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn generate_hole_punch_crypt_container<R: Ratchet>(
    ratchet: R,
    security_level: SecurityLevel,
    target_cid: u64,
    stun_servers: Option<Vec<String>>,
) -> citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer {
    use crate::proto::packet_crafter;
    use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;

    let ratchet_cloned = ratchet.clone();
    HolePunchConfigContainer::new(
        move |plaintext| {
            packet_crafter::hole_punch::generate_packet(
                &ratchet,
                plaintext,
                security_level,
                target_cid,
            )
        },
        move |packet| {
            packet_crafter::hole_punch::decrypt_packet(&ratchet_cloned, packet, security_level)
        },
        stun_servers,
    )
}
