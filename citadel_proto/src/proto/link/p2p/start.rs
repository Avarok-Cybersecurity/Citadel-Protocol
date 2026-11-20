//! A pair that may run under its link manager: everything `run_managed` needs except the
//! coordination endpoint, gathered when the key exchange finished. The campaign holds it until
//! the endpoint registered and both ends agreed (`agree`), then hands over or drops it.

use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_link::{
    ConnectionId, LinkConfig, LinkCore, LinkKind, LinkPolicy, LinkSettings, NatClass, PathPlan,
    PathStage, PeerCaps, TimedStage,
};
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use citadel_wire::udp_traversal::turn_relay::TurnRelayConfig;
use netbeam::sync::network_endpoint::NetworkEndpoint;

use super::context::{P2pLinkContext, WeakSession};
use super::establisher::P2pEstablisher;
use super::handles::P2pChannel;
use super::managed::{run_managed, P2pPorts};
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::local_rebind::LocalRebinder;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::p2p_path::P2pPathCell;
use crate::proto::peer::p2p_plan::{P2pPlan, PlanStep};
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use citadel_types::proto::timing::P2P_STAGE_TIMEOUT;

/// One pair's facts, for the manager.
pub(crate) struct ManagedPair<R: Ratchet, T: PlatformOps> {
    pub(crate) policy: LinkPolicy,
    /// The node's `ManagedLinks::clock`: every deadline of the pair's manager reads it.
    pub(crate) clock: Arc<dyn citadel_link::Clock>,
    pub(crate) session: WeakSession<R, T>,
    pub(crate) session_cid: DualRwLock<Option<u64>>,
    pub(crate) rebinder: LocalRebinder,
    pub(crate) peer_connection_type: PeerConnectionType,
    pub(crate) ticket: Ticket,
    pub(crate) connection: ConnectionId,
    pub(crate) security: SessionSecuritySettings,
    pub(crate) udp_mode: UdpMode,
    pub(crate) peer_nat_info: PeerNatInfo,
    pub(crate) local_nat: NatClass,
    pub(crate) endpoint_ratchet: R,
    pub(crate) turn: Option<TurnRelayConfig>,
    pub(crate) plan: P2pPlan,
    pub(crate) direct_impossible: bool,
    pub(crate) sync_time: Instant,
    pub(crate) cell: P2pPathCell,
}

/// The campaign's plan as the core names it, the server relay last: it carries the pair whenever
/// no route does, so its stage opens at once.
pub(crate) fn link_plan(plan: &P2pPlan, direct_impossible: bool) -> PathPlan {
    let mut stages: Vec<_> = plan
        .steps
        .iter()
        .map(|step| TimedStage {
            stage: match step.step {
                PlanStep::Direct => PathStage::Direct,
                PlanStep::Turn(_) => PathStage::Turn,
            },
            timeout: step.timeout,
        })
        .collect();
    stages.push(TimedStage {
        stage: PathStage::Relay,
        timeout: P2P_STAGE_TIMEOUT,
    });
    PathPlan {
        stages,
        turn_configured: plan.turn_configured,
        direct_impossible,
    }
}

impl<R: Ratchet, T: PlatformOps> ManagedPair<R, T> {
    /// Runs the pair's manager on the registered endpoint until the connection ends.
    pub(crate) async fn run(self, app: NetworkEndpoint) {
        let local_cid = self.peer_connection_type.get_original_session_cid();
        let peer_cid = self.peer_connection_type.get_original_target_cid();
        let peer_nat = self.peer_nat_info.peer_nat.class();
        let settings = LinkSettings {
            security: self.security,
            udp_mode: self.udp_mode,
        };
        let config = LinkConfig {
            kind: LinkKind::Peer {
                local_cid,
                peer_cid,
            },
            connection: self.connection,
            policy: self.policy,
            // Both ends carry the negotiation lane; a P2P route
            // is resealed under the live keys; a P2P seal is never reattached (C2S only).
            caps: PeerCaps {
                in_band: true,
                reseal: true,
                reattach: false,
            },
            settings,
            plan: None,
            local_nat: self.local_nat,
        };
        let core = match LinkCore::new(config) {
            Ok(core) => core,
            Err(err) => {
                log::error!(target: "citadel", "P2P link to {peer_cid} refused its config ({err:?}); it stays on the server relay");
                return;
            }
        };
        let plan = link_plan(&self.plan, self.direct_impossible);
        let ports = P2pPorts::new(app.clone(), plan, peer_cid, self.rebinder);
        let ctx = P2pLinkContext {
            session: self.session,
            session_cid: self.session_cid,
            local_cid,
            peer_cid,
            peer_connection_type: self.peer_connection_type,
            ticket: self.ticket,
            connection: self.connection,
            security: self.security,
            peer_nat_info: self.peer_nat_info,
            local_nat: self.local_nat,
            peer_nat,
            app,
            endpoint_ratchet: self.endpoint_ratchet,
            turn: self.turn,
            sync_time: self.sync_time,
        };
        let clock = self.clock;
        let establisher = P2pEstablisher {
            ctx: Arc::new(ctx),
            clock: clock.clone(),
        };
        let channel = P2pChannel::held_by_the_kernel();
        run_managed(core, establisher, ports, clock, channel, self.cell).await;
    }
}

/// Runs the pair under its manager when both ends are Managed (`agree`); `false` leaves the
/// pair to the campaign. Every node takes part in the exchange, Legacy too.
pub(crate) async fn hand_over<R: Ratchet, T: PlatformOps>(
    managed: Option<ManagedPair<R, T>>,
    app: &NetworkEndpoint,
) -> bool {
    let agreed = super::agree::agree_mode(app, managed.is_some()).await;
    match (agreed, managed) {
        (true, Some(pair)) => {
            pair.run(app.clone()).await;
            true
        }
        _ => false,
    }
}
