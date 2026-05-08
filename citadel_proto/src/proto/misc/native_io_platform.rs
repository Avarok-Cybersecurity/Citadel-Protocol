//! `PlatformOps` implementation for `NativeIO`.
//!
//! Provides real NAT traversal, file I/O, and UDP session management
//! on native (non-WASM) targets. UDP socket loading is delegated to
//! [`native_io_udp`](super::native_io_udp).
#![allow(clippy::manual_async_fn)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{SessionSecuritySettings, UdpMode, VirtualObjectMetadata};
use citadel_wire::exports::Connection;
use citadel_wire::nat_identification::NatType;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::RelativeNodeType;

use super::native_io::NativeIO;
use super::platform_ops::PlatformOps;
use super::udp_internal_interface::{
    QuicUdpSocketConnector, RawUdpSocketConnector, UdpSplittableTypes,
};
use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use crate::proto::node_result::NodeResult;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::p2p_conn_handler;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualTargetType;

#[allow(private_interfaces)]
impl PlatformOps for NativeIO {
    fn identify_nat_type(
        stun_servers: Option<Vec<String>>,
    ) -> impl std::future::Future<Output = std::io::Result<NatType>> + ContextRequirements {
        async {
            NatType::identify(stun_servers)
                .await
                .map_err(|e| std::io::Error::other(format!("NAT identification failed: {e}")))
        }
    }

    fn quic_udp_channel(conn: Connection, local_addr: SocketAddr) -> Option<UdpSplittableTypes> {
        log::trace!(target: "citadel", "Will use QUIC UDP for UDP transmission");
        Some(UdpSplittableTypes::Quic(QuicUdpSocketConnector::new(
            conn, local_addr,
        )))
    }

    fn c2s_hole_punch<R: Ratchet>(
        stream: ReliableOrderedCompatStream<R>,
        ratchet: R,
        security_level: SecurityLevel,
        target_cid: u64,
        stun_servers: Option<Vec<String>>,
        node_type: RelativeNodeType,
    ) -> impl std::future::Future<Output = Result<Option<UdpSplittableTypes>, NetworkError>>
           + ContextRequirements {
        async move {
            let endpoint = NetworkEndpoint::register(node_type, stream)
                .await
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
            log::trace!(target: "citadel", "{node_type:?} created for C2S hole punch");

            let config = generate_hole_punch_crypt_container(
                ratchet,
                security_level,
                target_cid,
                stun_servers,
            );

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
    }

    #[allow(clippy::too_many_arguments)]
    fn p2p_hole_punch<R: Ratchet>(
        session: CitadelSession<R, Self>,
        peer_connection_type: PeerConnectionType,
        ticket: Ticket,
        peer_nat_info: PeerNatInfo,
        channel_signal: NodeResult<R>,
        hole_punch_compat_stream: ReliableOrderedCompatStream<R>,
        endpoint_ratchet: R,
        peer_cid: u64,
        sync_instant: citadel_io::time::Instant,
        node_type: RelativeNodeType,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        cancel_rx: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) -> impl std::future::Future<Output = Result<(), NetworkError>> + ContextRequirements {
        async move {
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
    }

    fn open_and_validate_for_transfer(
        source_path: &Path,
        expected_metadata: Option<&VirtualObjectMetadata>,
    ) -> Result<super::platform_ops::TransferMetadata, NetworkError> {
        use citadel_crypt::prelude::FixedSizedSource;

        let file = std::fs::File::open(source_path)
            .map_err(|err: std::io::Error| NetworkError::Generic(err.to_string()))?;

        if let Some(virtual_object_metadata) = expected_metadata {
            let expected_min_length = virtual_object_metadata.plaintext_length;
            let file_length = file
                .length()
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
            if file_length < expected_min_length as u64 {
                log::warn!(target: "citadel", "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem: Current file length: {file_length}, expected min length: {expected_min_length}");
                return Err(NetworkError::InternalError(
                    "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem",
                ));
            }
        }

        file.metadata()
            .map(Into::into)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn async_delete_file(source: PathBuf) {
        spawn!(citadel_io::tokio::fs::remove_file(source));
    }

    fn spawn_udp_socket_loader<R: Ratchet>(
        session: CitadelSession<R, Self>,
        v_target: VirtualTargetType,
        udp_conn: UdpSplittableTypes,
        addr: TargettedSocketAddr,
        ticket: Ticket,
        tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) {
        super::native_io_udp::spawn(session, v_target, udp_conn, addr, ticket, tcp_conn_awaiter);
    }
}

/// Generate a `HolePunchConfigContainer` with encryption/decryption closures.
fn generate_hole_punch_crypt_container<R: Ratchet>(
    ratchet: R,
    security_level: SecurityLevel,
    target_cid: u64,
    stun_servers: Option<Vec<String>>,
) -> HolePunchConfigContainer {
    use crate::proto::packet_crafter;

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
