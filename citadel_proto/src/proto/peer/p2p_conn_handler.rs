/*!
# P2P Connection Handler Module

This module implements direct peer-to-peer connection handling and NAT traversal functionality for the Citadel Protocol, enabling secure direct connections between peers.

## Features
- **Direct P2P Connections**: Manages direct peer-to-peer connections with support for both TCP and UDP
- **NAT Traversal**: Implements UDP hole punching for NAT traversal
- **Connection Management**: Handles connection setup, teardown, and error recovery
- **WebRTC Support**: Compatible with WebRTC for web-based peer connections
- **Security**: Integrates with Citadel's security infrastructure for encrypted communications

## Core Components
- `DirectP2PRemote`: Manages direct P2P connection state and lifecycle
- `P2PInboundHandle`: Handles incoming P2P connections and related state
- `attempt_simultaneous_hole_punch`: Implements NAT traversal via UDP hole punching
- `PeerNatInfo`: Handles NAT detection and compatibility checking

## Important Notes
1. Supports both TCP and UDP connections with automatic fallback
2. Implements symmetric NAT traversal through coordinated hole punching
3. Handles connection cleanup and resource management
4. Integrates with Citadel's session and security infrastructure

## Related Components
- `peer_layer`: High-level peer networking abstraction
- `peer_crypt`: Handles peer-to-peer encryption
- `session`: Manages connection sessions
- `state_container`: Tracks connection state

*/

use citadel_io::tokio::sync::oneshot::Sender;

use crate::functional::IfTrueConditional;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::NodeResult;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::outbound_sender::UnboundedSender;
use crate::proto::packet_processor::includes::{Duration, Instant, SocketAddr};
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::{CitadelSession, SessionAliveTracker};
use crate::proto::state_container::VirtualConnectionType;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::prelude::{SessionSecuritySettings, UdpMode};
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::sync::Arc;

pub struct DirectP2PRemote {
    // immediately causes connection to end
    pub(crate) stopper: Option<Sender<()>>,
    pub p2p_primary_stream: OutboundPrimaryStreamSender,
    pub from_listener: bool,
    /// Identifies this route among every route a node attaches, so the handler of a route that
    /// ended can tell whether it is still the connection's route.
    pub(crate) route_id: u64,
}

/// A fresh [`DirectP2PRemote::route_id`].
pub(crate) fn next_route_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Debug for DirectP2PRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectP2PRemote")
            .field("from_listener", &self.from_listener)
            .finish()
    }
}

impl DirectP2PRemote {
    /// - quic_connector should be Some for server conns, None for clients
    pub(crate) fn new(
        stopper: Sender<()>,
        p2p_primary_stream: OutboundPrimaryStreamSender,
        from_listener: bool,
        route_id: u64,
    ) -> Self {
        Self {
            stopper: Some(stopper),
            p2p_primary_stream,
            from_listener,
            route_id,
        }
    }
}

impl Drop for DirectP2PRemote {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "[DirectP2PRemote] dropping p2p connection (type: {})...", self.from_listener.if_true("listener").if_false("client"));
        if let Some(stopper) = self.stopper.take() {
            if stopper.send(()).is_err() {
                //log::error!(target: "citadel", "Unable to alert p2p-stopper")
            }
        }
    }
}

pub struct P2PInboundHandle<R: Ratchet> {
    pub remote_peer: SocketAddr,
    pub local_bind_port: u16,
    // this has to be the CID of the local session, not the peer's CID
    pub session_cid: DualRwLock<Option<u64>>,
    pub kernel_tx: UnboundedSender<NodeResult<R>>,
    pub to_primary_stream: OutboundPrimaryStreamSender,
    pub peer_cid: u64,
    /// The P2P connection this stream carries, named in the disconnect its end reports.
    pub p2p_connection_id: Ticket,
}

impl<R: Ratchet> P2PInboundHandle<R> {
    pub(crate) fn new(
        remote_peer: SocketAddr,
        local_bind_port: u16,
        session_cid: DualRwLock<Option<u64>>,
        kernel_tx: UnboundedSender<NodeResult<R>>,
        to_primary_stream: OutboundPrimaryStreamSender,
        peer_cid: u64,
        p2p_connection_id: Ticket,
    ) -> Self {
        Self {
            remote_peer,
            local_bind_port,
            session_cid,
            kernel_tx,
            to_primary_stream,
            peer_cid,
            p2p_connection_id,
        }
    }
}

pub(crate) fn generic_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    err: E,
) -> std::io::Error {
    std::io::Error::other(err)
}

#[cfg(not(target_family = "wasm"))]
pub(crate) mod native_p2p {
    use super::*;
    use crate::proto::link::p2p::attach::attach_p2p_stream;
    use crate::proto::link::p2p::direct::{open_direct_path, DirectStage};
    use crate::proto::link::p2p::wrap::{wrap_p2p_stream, RouteFacts};
    use crate::proto::misc::net::GenericNetworkStream;
    use crate::proto::peer::p2p_outcome::{
        tried, AtStage, AttemptReport, PathStage, StageError, StageFailure,
    };
    use citadel_wire::exports::tokio_rustls::rustls;
    use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
    use citadel_wire::udp_traversal::udp_hole_puncher::PunchBudget;

    /// Seals and delivers a P2P QUIC stream as its connection's route: [`wrap_p2p_stream`]
    /// then [`attach_p2p_stream`] (`link::p2p`), the two steps the manager runs apart.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_p2p_stream<R: Ratchet, T: PlatformOps>(
        p2p_stream: GenericNetworkStream,
        session_cid: DualRwLock<Option<u64>>,
        session: CitadelSession<R, T>,
        kernel_tx: UnboundedSender<NodeResult<R>>,
        from_listener: bool,
        v_conn: VirtualConnectionType,
        hole_punched_addr: TargettedSocketAddr,
        ticket: Ticket,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        path: P2pRoute,
    ) -> std::io::Result<()> {
        let facts = RouteFacts {
            route_id: super::next_route_id(),
            from_listener,
            v_conn,
            hole_punched_addr,
            ticket,
            udp_mode,
            session_security_settings,
            path,
        };
        let wrapped = wrap_p2p_stream(p2p_stream, session_cid, session, kernel_tx, facts)?;
        attach_p2p_stream(wrapped)
    }

    /// One upgrade attempt: hole punch (unless the plan skips it), then TURN when a relay is
    /// configured and the punch did not succeed. Both sides begin at `sync_time`. Reports each
    /// stage it ran, with the reason for any that failed, and the route it attached. The caller
    /// cancels by dropping the future (the campaign does, on session shutdown).
    #[cfg_attr(feature = "localhost-testing", tracing::instrument(
        level = "trace",
        target = "citadel",
        skip_all,
        ret,
        fields(session_cid=session_cid.get(), peer_cid=peer_connection_type.get_original_target_cid()
        )
    ))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn attempt_simultaneous_hole_punch<R: Ratchet, T: PlatformOps>(
        peer_connection_type: PeerConnectionType,
        ticket: Ticket,
        session: CitadelSession<R, T>,
        peer_nat_info: PeerNatInfo,
        session_cid: DualRwLock<Option<u64>>,
        kernel_tx: UnboundedSender<NodeResult<R>>,
        sync_time: Instant,
        app: NetworkEndpoint,
        encrypted_config_container: HolePunchConfigContainer,
        stun_servers: citadel_wire::stun_servers::StunServers,
        client_config: T::ClientConfig,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        session_alive: SessionAliveTracker<R, T>,
        steps: Vec<crate::proto::peer::p2p_plan::TimedStep>,
    ) -> AttemptReport {
        let Some(client_config) = T::client_config_to_any(&client_config)
            .and_then(|c| c.downcast::<Arc<rustls::ClientConfig>>().ok())
            .map(|c| *c)
        else {
            log::warn!(target: "citadel", "P2P hole-punch requires native rustls client config");
            let unsupported = tried(
                PathStage::Direct,
                Err(StageFailure::Unsupported),
                Duration::ZERO,
            );
            return AttemptReport::nothing_attached(vec![unsupported]);
        };
        let kernel_tx = &kernel_tx;
        let v_conn = peer_connection_type.as_virtual_connection();
        let relay_app = app.clone();
        let relay_session = session.clone();
        let relay_session_cid = session_cid.clone();
        let relay_nat_info = peer_nat_info.clone();
        let relay_tls = client_config.clone();

        let process = move |punch_budget: PunchBudget| async move {
            if !session_alive.alive() {
                return Err(StageError::new(
                    StageFailure::SessionGone,
                    "session no longer alive",
                ));
            }
            let direct = open_direct_path(DirectStage {
                app,
                sync_time,
                cipher: encrypted_config_container,
                stun_servers,
                tls: client_config,
                peer_nat_info,
                budget: punch_budget,
            })
            .await?;
            let punch = direct.punch;
            log::trace!(target: "citadel", "[Hole-punch] punched on attempt {}/{} in {:?} (local NAT {:?})", punch.attempt, punch.attempts_allowed, punch.elapsed, punch.local_nat);
            handle_p2p_stream(
                direct.stream,
                session_cid,
                session.clone(),
                kernel_tx.clone(),
                direct.from_listener,
                v_conn,
                direct.addr,
                ticket,
                udp_mode,
                session_security_settings,
                P2pRoute::Direct,
            )
            .at(StageFailure::AttachFailed)
        };

        use crate::proto::peer::p2p_plan::PlanStep;
        // The punch's attempts are cut from the Direct stage's own timeout, the same on both ends.
        let mut direct = steps
            .iter()
            .find(|s| matches!(s.step, PlanStep::Direct))
            .map(|s| process(PunchBudget::within_stage(s.timeout)));
        let mut stages = Vec::with_capacity(steps.len());
        let mut route = None;
        if !steps.iter().any(|s| matches!(s.step, PlanStep::Direct)) {
            log::info!(target: "citadel", "[Hole-punch] skipped: the plan does not try it");
        }
        // Each planned path in order, each with its own attempt timeout, until one attaches.
        for planned in steps {
            if route.is_some() {
                break;
            }
            let started = Instant::now();
            let timeout = planned.timeout;
            let (stage, result) = match planned.step {
                PlanStep::Direct => {
                    let Some(process) = direct.take() else {
                        continue;
                    };
                    let result = match citadel_io::time::timeout(timeout, process).await {
                        Ok(Ok(())) => {
                            log::trace!(target: "citadel", "[Hole-punch] P2P connection established successfully");
                            route = Some(P2pRoute::Direct);
                            Ok(())
                        }
                        Ok(Err(err)) => {
                            log::warn!(target: "citadel", "[Hole-punch/Err] {err}");
                            Err(err.failure)
                        }
                        Err(_elapsed) => {
                            log::warn!(target: "citadel", "[Hole-punch/Timeout] P2P connection establishment timed out after {timeout:?}");
                            Err(StageFailure::Timeout)
                        }
                    };
                    (PathStage::Direct, result)
                }
                PlanStep::Turn(relay) => {
                    let relayed = crate::proto::link::p2p::turn::establish_relayed_p2p(
                        &relay_app,
                        relay,
                        relay_session.clone(),
                        relay_session_cid.clone(),
                        &relay_nat_info,
                        v_conn,
                        ticket,
                        udp_mode,
                        session_security_settings,
                        relay_tls.clone(),
                    );
                    let result = match citadel_io::time::timeout(timeout, relayed).await {
                        Ok(Ok(relayed_route)) => {
                            route = Some(relayed_route);
                            log::info!(target: "citadel", "[TURN] P2P connection established over the relay");
                            Ok(())
                        }
                        Ok(Err(err)) => {
                            log::warn!(target: "citadel", "[TURN/Err] relay unavailable: {err}");
                            Err(err.failure)
                        }
                        Err(_) => {
                            log::warn!(target: "citadel", "[TURN/Timeout] relay attempt timed out after {timeout:?}");
                            Err(StageFailure::Timeout)
                        }
                    };
                    (PathStage::Turn, result)
                }
            };
            stages.push(tried(stage, result, started.elapsed()));
        }

        AttemptReport { stages, route }
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) use native_p2p::attempt_simultaneous_hole_punch;
