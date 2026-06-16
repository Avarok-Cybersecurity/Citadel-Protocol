//! PlatformOps trait — SSOT for platform-specific capabilities.
//!
//! Extends [`ProtocolIO`] (transport abstraction) with platform-specific
//! operations: NAT traversal, file I/O, UDP session management.
//! [`NativeIO`](super::native_io::NativeIO) and
//! [`WasmIO`](super::wasm_io::WasmIO) each provide implementations so
//! the protocol layer remains platform-agnostic.

use citadel_io::time::SystemTime;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use citadel_crypt::ratchets::Ratchet;
use citadel_io::ProtocolIO;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{SessionSecuritySettings, UdpMode, VirtualObjectMetadata};
use citadel_wire::exports::Connection;
#[cfg(target_family = "wasm")]
use citadel_wire::hypernode_type::NodeType;
use citadel_wire::nat_identification::NatType;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use netbeam::sync::RelativeNodeType;

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use crate::proto::misc::udp_internal_interface::UdpSplittableTypes;
use crate::proto::node_result::NodeResult;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualTargetType;
use citadel_io::{error, ErrorCode};

/// Platform-portable file metadata returned by [`PlatformOps::open_and_validate_for_transfer`].
///
/// Wraps only the fields the protocol actually needs, avoiding `std::fs::Metadata`
/// which cannot be constructed on WASM.
pub struct TransferMetadata {
    pub len: u64,
    pub created: Option<SystemTime>,
}

#[cfg(not(target_family = "wasm"))]
impl From<std::fs::Metadata> for TransferMetadata {
    fn from(m: std::fs::Metadata) -> Self {
        Self {
            len: m.len(),
            created: m.created().ok(),
        }
    }
}

/// Platform-specific capabilities extending the transport abstraction.
///
/// [`ProtocolIO`] defines *how* bytes move on the wire.
/// `PlatformOps` defines *what the platform can do*: NAT traversal, file I/O,
/// UDP session management, P2P hole punching.
///
/// Each platform (`NativeIO`, `WasmIO`) provides its own implementation.
/// Business logic uses `T: PlatformOps` and calls `T::method()` directly —
/// no cfg gates, no dispatch modules.
#[allow(private_interfaces)]
pub trait PlatformOps: ProtocolIO {
    // ── NAT identification ──

    /// Identify local NAT type via STUN servers.
    /// Default: returns `NatType::offline()` (appropriate for WASM).
    fn identify_nat_type(
        stun_servers: Option<Vec<String>>,
    ) -> impl Future<Output = io::Result<NatType>> + ContextRequirements {
        async move {
            let _ = stun_servers;
            Ok(NatType::offline())
        }
    }

    /// Create a UDP channel from an existing QUIC connection.
    /// Default: returns `None` (QUIC not available).
    fn quic_udp_channel(conn: Connection, local_addr: SocketAddr) -> Option<UdpSplittableTypes> {
        let _ = (conn, local_addr);
        None
    }

    // ── Hole punching ──

    /// Perform C2S UDP hole punch via `NetworkEndpoint` + encrypted hole punch.
    /// Returns the resulting UDP interface, or `None` if unavailable.
    /// Default: returns `Ok(None)` (hole punching not available).
    fn c2s_hole_punch<R: Ratchet>(
        stream: ReliableOrderedCompatStream<R>,
        ratchet: R,
        security_level: SecurityLevel,
        target_cid: u64,
        stun_servers: Option<Vec<String>>,
        node_type: RelativeNodeType,
    ) -> impl Future<Output = Result<Option<UdpSplittableTypes>, NetworkError>> + ContextRequirements
    {
        async move {
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

    /// Orchestrate P2P hole punch: register endpoint, punch, establish
    /// connection, send `channel_signal` to kernel.
    /// On failure (or on WASM), sends `channel_signal` as TCP-only fallback.
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
    ) -> impl Future<Output = Result<(), NetworkError>> + ContextRequirements;

    // ── File I/O ──

    /// Open a file and validate it for transfer.
    /// Default: returns an error (file transfer not supported).
    fn open_and_validate_for_transfer(
        source_path: &Path,
        expected_metadata: Option<&VirtualObjectMetadata>,
    ) -> Result<TransferMetadata, NetworkError> {
        let _ = (source_path, expected_metadata);
        Err(error!(ErrorCode::FileTransferPlatformUnsupported))
    }

    /// Asynchronously delete a file after transfer.
    /// Default: no-op.
    fn async_delete_file(source: PathBuf) {
        let _ = source;
    }

    // ── UDP session ──

    /// Spawn the UDP socket loader for a session.
    /// On native: spawns an async task for the full UDP subsystem.
    /// Default: no-op.
    fn spawn_udp_socket_loader<R: Ratchet>(
        session: CitadelSession<R, Self>,
        v_target: VirtualTargetType,
        udp_conn: UdpSplittableTypes,
        addr: TargettedSocketAddr,
        ticket: Ticket,
        tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) {
        let _ = (session, v_target, udp_conn, addr, ticket, tcp_conn_awaiter);
    }

    // ── Serverless transport (WASM only) ──

    /// Create the listener/client-config/node-type tuple for serverless mode.
    ///
    /// Moves the pre-established stream into either a listener (server role)
    /// or a client config with a pre-built stream (client role), returning
    /// the correct associated types for the generic `build()` pipeline.
    #[cfg(target_family = "wasm")]
    fn setup_serverless_transport(
        stream: super::wasm_stream::WasmStream,
        is_server_role: bool,
        existing_client_config: Option<Self::ClientConfig>,
    ) -> (Option<Self::Listener>, Option<Self::ClientConfig>, NodeType);
}

/// Platform-appropriate default transport.
///
/// Resolves to `NativeIO` on native targets and `WasmIO` on WASM.
#[cfg(not(target_family = "wasm"))]
pub type DefaultTransport = super::native_io::NativeIO;
/// Platform-appropriate default transport.
///
/// Resolves to `NativeIO` on native targets and `WasmIO` on WASM.
#[cfg(target_family = "wasm")]
pub type DefaultTransport = super::wasm_io::WasmIO;
