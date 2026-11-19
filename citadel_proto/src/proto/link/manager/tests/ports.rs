//! The scripted ports and the explicit policy and config every shell test runs with.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use citadel_io::Mutex;
use citadel_link::{
    BufferMode, ConnectionId, Fut, LinkConfig, LinkEvent, LinkKind, LinkSettings, NatClass,
    PathPlan, PathStage, PeerCaps, RendezvousVia, RouteId, StageFailure, TimedStage,
};

use crate::proto::link::manager::ports::LinkPorts;

/// Ports that meet at once with `plan`, and record what was reported.
pub(super) struct ScriptedPorts {
    pub(super) plan: PathPlan,
    pub(super) met: AtomicU32,
    pub(super) events: Mutex<Vec<LinkEvent>>,
    pub(super) buffers: Mutex<VecDeque<BufferMode>>,
    pub(super) fallbacks: AtomicU32,
}

impl LinkPorts for ScriptedPorts {
    fn rendezvous(&self, _: u32, _: RendezvousVia) -> Fut<'_, Result<PathPlan, StageFailure>> {
        self.met.fetch_add(1, Ordering::SeqCst);
        let plan = self.plan.clone();
        Box::pin(async move { Ok(plan) })
    }
    fn rebind(&self, _: RouteId) -> Fut<'_, bool> {
        Box::pin(async { false })
    }
    fn probe(&self) -> Fut<'_, bool> {
        Box::pin(async { true })
    }
    fn fall_back_to_relay(&self) {
        self.fallbacks.fetch_add(1, Ordering::SeqCst);
    }
    fn report(&self, event: LinkEvent) {
        self.events.lock().push(event);
    }
    fn buffer(&self, mode: BufferMode) {
        self.buffers.lock().push_back(mode);
    }
}

pub(super) fn nat() -> NatClass {
    use citadel_types::proto::{IpTranslationClass, PortTranslationClass};
    NatClass {
        ip_translation: IpTranslationClass::Constant,
        port_translation: PortTranslationClass::Identity,
        ipv6_enabled: false,
    }
}

pub(super) use crate::proto::link::test_policy::policy;

pub(super) fn direct_then_relay() -> PathPlan {
    let stage = |stage, secs| TimedStage {
        stage,
        timeout: Duration::from_secs(secs),
    };
    PathPlan {
        stages: vec![stage(PathStage::Direct, 30), stage(PathStage::Relay, 10)],
        turn_configured: false,
        direct_impossible: false,
    }
}

pub(super) fn config(local_cid: u64, peer_cid: u64, settings: LinkSettings) -> LinkConfig {
    let caps = PeerCaps {
        in_band: true,
        reseal: true,
        reattach: false,
    };
    LinkConfig {
        kind: LinkKind::Peer {
            local_cid,
            peer_cid,
        },
        connection: ConnectionId(7),
        policy: policy(),
        caps,
        settings,
        plan: None,
        local_nat: nat(),
    }
}
