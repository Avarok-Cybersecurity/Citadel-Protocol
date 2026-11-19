//! The TURN stage, split like the direct one: [`open_relayed_path`] (in `peer::turn_p2p`) is the
//! path, and the campaign's [`establish_relayed_p2p`] seals and delivers it.

use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::turn_relay::TurnRelayConfig;
use netbeam::sync::network_endpoint::NetworkEndpoint;

use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::p2p_conn_handler::native_p2p::handle_p2p_stream;
use crate::proto::peer::p2p_outcome::{AtStage, StageError, StageFailure};
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::turn_p2p::open_relayed_path;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualConnectionType;

/// Connects the two peers through TURN and installs the result as their direct P2P connection
/// (path [`P2pPath::Turn`](crate::proto::peer::p2p_path::P2pPath::Turn)); the UDP channel is then
/// fulfilled over it. Returns the route it attached, or the step that failed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn establish_relayed_p2p<R: Ratchet, T: PlatformOps>(
    app: &NetworkEndpoint,
    config: TurnRelayConfig,
    session: CitadelSession<R, T>,
    session_cid: DualRwLock<Option<u64>>,
    peer_nat_info: &PeerNatInfo,
    v_conn: VirtualConnectionType,
    ticket: Ticket,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
    tls: Arc<rustls::ClientConfig>,
) -> Result<P2pRoute, StageError> {
    let local_cid = session_cid
        .get()
        .ok_or_else(|| StageError::new(StageFailure::SessionGone, "session CID not loaded"))?;
    let relayed = open_relayed_path(
        app,
        &config,
        local_cid,
        v_conn.get_target_cid(),
        peer_nat_info,
        tls,
    )
    .await?;
    let kernel_tx = session.kernel_tx.clone();
    handle_p2p_stream(
        relayed.stream,
        session_cid,
        session,
        kernel_tx,
        relayed.from_listener,
        v_conn,
        relayed.addr,
        ticket,
        udp_mode,
        session_security_settings,
        relayed.route,
    )
    .at(StageFailure::AttachFailed)?;
    Ok(relayed.route)
}

/// A QUIC connection through TURN, not yet sealed.
pub(crate) struct RelayedPath {
    pub(crate) stream: GenericNetworkStream,
    pub(crate) addr: TargettedSocketAddr,
    pub(crate) from_listener: bool,
    pub(crate) route: P2pRoute,
}
