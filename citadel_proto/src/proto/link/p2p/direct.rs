//! Path: one direct stage of a P2P attempt, the hole punch and the QUIC handshake over the
//! punched socket (the attempt body of `attempt_simultaneous_hole_punch`, with the seal and the
//! delivery taken out). Both sides begin at `sync_time`; the initiator dials, the other side
//! listens on the same socket, and `DIRECT_READY` orders the listener before the dial.

use std::sync::Arc;

use citadel_io::time::Instant;
use citadel_io::tokio_stream::StreamExt;
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use citadel_wire::udp_traversal::udp_hole_puncher::{
    EndpointHolePunchExt, PunchBudget, PunchReport,
};
use netbeam::sync::network_endpoint::NetworkEndpoint;

use crate::proto::misc::native_connect::{p2p_connect_from_socket, p2p_listener_from_socket};
use crate::proto::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::proto::peer::coordination::DIRECT_READY;
use crate::proto::peer::p2p_outcome::{AtStage, StageError, StageFailure};
use crate::proto::peer::peer_crypt::PeerNatInfo;

/// What one direct stage needs.
pub(crate) struct DirectStage {
    pub(crate) app: NetworkEndpoint,
    pub(crate) sync_time: Instant,
    pub(crate) cipher: HolePunchConfigContainer,
    pub(crate) stun_servers: citadel_wire::stun_servers::StunServers,
    pub(crate) tls: Arc<rustls::ClientConfig>,
    pub(crate) peer_nat_info: PeerNatInfo,
    pub(crate) budget: PunchBudget,
}

/// A direct path: a QUIC connection over a punched socket, not yet sealed.
pub(crate) struct DirectPath {
    pub(crate) stream: GenericNetworkStream,
    pub(crate) addr: TargettedSocketAddr,
    /// This side accepted the connection (the non-initiator).
    pub(crate) from_listener: bool,
    pub(crate) punch: PunchReport,
}

/// Opens the direct path: punch, then dial (initiator) or accept (the other side).
pub(crate) async fn open_direct_path(stage: DirectStage) -> Result<DirectPath, StageError> {
    let DirectStage {
        app,
        sync_time,
        cipher,
        stun_servers,
        tls,
        peer_nat_info,
        budget,
    } = stage;
    let is_initiator = app.is_initiator();
    citadel_io::time::sleep_until(sync_time).await;

    let punched = app
        .begin_udp_hole_punch(cipher, stun_servers, budget)
        .reported()
        .await
        .at(StageFailure::PunchFailed)?;
    let (hole_punched_socket, punch) = (punched.socket, punched.report);
    let direct_ready = app.on(DIRECT_READY);
    let remote_connect_addr = hole_punched_socket.addr.send_address;
    let addr = hole_punched_socket.addr;
    let local_addr = hole_punched_socket
        .local_addr()
        .at(StageFailure::LocalSocket)?;
    log::trace!(target: "citadel", "~!@ P2P UDP Hole-punch finished @!~ | is initiator: {is_initiator}");
    let socket = hole_punched_socket.into_socket();

    if is_initiator {
        direct_ready.sync().await.at(StageFailure::Signalling)?;
        log::trace!(target: "citadel", "Initiator: sync complete, non-initiator listener should be ready");
        let stream = p2p_connect_from_socket(
            socket,
            remote_connect_addr,
            peer_nat_info.tls_domain,
            tls,
            None,
        )
        .await
        .at(StageFailure::HandshakeFailed)?;
        log::trace!(target: "citadel", "~!@ P2P UDP Hole-punch + QUIC finished successfully for INITIATOR @!~");
        return Ok(DirectPath {
            stream,
            addr,
            from_listener: false,
            punch,
        });
    }

    log::trace!(target: "citadel", "Non-initiator: creating listener before signaling ready");
    let (listener, _) =
        p2p_listener_from_socket(socket, None, local_addr).at(StageFailure::LocalSocket)?;
    log::trace!(target: "citadel", "Non-initiator: listener created (socket reused) on {:?}, signaling ready", local_addr);
    direct_ready.sync().await.at(StageFailure::Signalling)?;
    let stream = accept_one(listener).await?;
    Ok(DirectPath {
        stream,
        addr,
        from_listener: true,
        punch,
    })
}

/// Accepts the one QUIC connection a P2P listener on a punched or relayed socket waits for.
pub(crate) async fn accept_one(
    mut listener: GenericNetworkListener,
) -> Result<GenericNetworkStream, StageError> {
    match listener.next().await {
        Some(Ok((stream, _))) => Ok(stream),
        Some(Err(err)) => {
            log::error!(target: "citadel", "[P2P-stream] ERR: {err:?}");
            Err(StageError::new(
                StageFailure::HandshakeFailed,
                err.to_string(),
            ))
        }
        None => {
            log::error!(target: "citadel", "P2P listener returned None. Stream dead");
            Err(StageError::new(
                StageFailure::HandshakeFailed,
                "the P2P listener ended before a connection arrived",
            ))
        }
    }
}
