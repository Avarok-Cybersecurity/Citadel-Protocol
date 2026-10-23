//! What one P2P attempt tries, in which order, and for how long: the steps of a connection's
//! upgrade campaign.
//!
//! With a plan the server stamped into the key exchange (see `kex_path`), both peers build their
//! steps from it: each planned path before the server relay, with that path's own attempt
//! timeout. Without one (an older peer or server), each peer plans alone with [`plan_p2p`],
//! exactly as before path policies: its own TURN config and the NAT verdict, 30 s per stage.
//! Pure: no I/O, no clock.

use std::time::Duration;

use citadel_types::proto::{EffectivePlan, PathKind};
use citadel_wire::udp_traversal::turn_relay::{TurnPolicy, TurnRelayConfig};

use super::p2p_outcome::{PathPlanKind, PathStage};

/// The attempt timeout of each stage of a plan made without a stamped plan: the hole punch with
/// its QUIC handshake, and one relay attempt (allocation, signalling, probing and the handshake).
pub(crate) const LEGACY_DIRECT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const LEGACY_TURN_TIMEOUT: Duration = Duration::from_secs(30);

/// One path to try.
#[derive(Clone, Debug)]
pub(crate) enum PlanStep {
    /// Hole punch, then QUIC over the punched socket.
    Direct,
    /// QUIC through a TURN relay.
    Turn(TurnRelayConfig),
}

impl PlanStep {
    pub(crate) fn stage(&self) -> PathStage {
        match self {
            PlanStep::Direct => PathStage::Direct,
            PlanStep::Turn(_) => PathStage::Turn,
        }
    }
}

/// A step and how long it may take.
#[derive(Clone, Debug)]
pub(crate) struct TimedStep {
    pub(crate) step: PlanStep,
    pub(crate) timeout: Duration,
}

/// The steps of one attempt, in order. Empty: no P2P attempt; the connection stays on the
/// server relay.
#[derive(Clone, Debug)]
pub(crate) struct P2pPlan {
    pub(crate) steps: Vec<TimedStep>,
    /// Whether this peer held a TURN config when the plan was made, for reporting why a plan
    /// without a Turn step does not try one.
    pub(crate) turn_configured: bool,
}

impl P2pPlan {
    pub(crate) fn is_server_only(&self) -> bool {
        self.steps.is_empty()
    }

    pub(crate) fn tries(&self, stage: PathStage) -> bool {
        self.steps.iter().any(|s| s.step.stage() == stage)
    }

    pub(crate) fn kind(&self) -> PathPlanKind {
        let stages: Vec<_> = self.steps.iter().map(|s| s.step.stage()).collect();
        match stages.as_slice() {
            [] => PathPlanKind::ServerOnly,
            [PathStage::Direct] => PathPlanKind::DirectOnly,
            [PathStage::Turn] => PathPlanKind::TurnOnly,
            [PathStage::Turn, PathStage::Direct] => PathPlanKind::TurnThenDirect,
            _ => PathPlanKind::DirectThenTurn,
        }
    }
}

fn step(step: PlanStep, timeout: Duration) -> TimedStep {
    TimedStep { step, timeout }
}

/// The plan a peer makes alone, from its own TURN config and the (symmetric) NAT verdict: the
/// behaviour of every peer before path policies, and of every pair without a stamped plan.
pub(crate) fn plan_p2p(direct_impossible: bool, turn: Option<TurnRelayConfig>) -> P2pPlan {
    let turn_configured = turn.is_some();
    let direct = || step(PlanStep::Direct, LEGACY_DIRECT_TIMEOUT);
    let relay = |cfg| step(PlanStep::Turn(cfg), LEGACY_TURN_TIMEOUT);
    let steps = match turn {
        None if direct_impossible => vec![],
        None => vec![direct()],
        Some(cfg) if direct_impossible || cfg.policy == TurnPolicy::RelayOnly => vec![relay(cfg)],
        Some(cfg) => vec![direct(), relay(cfg)],
    };
    P2pPlan {
        steps,
        turn_configured,
    }
}

/// The plan for an attempt: the stamped plan's paths before the server relay, in order, each
/// with its own timeout, when the server stamped one; otherwise [`plan_p2p`]. A stamped Turn
/// step needs this peer's TURN config, and is skipped without one. PeerRelay is never planned
/// without a forwarder, and no forwarder exists yet, so it is skipped too.
pub(crate) fn execution_plan(
    stamped: Option<&EffectivePlan>,
    direct_impossible: bool,
    turn: Option<TurnRelayConfig>,
) -> P2pPlan {
    let Some(stamped) = stamped else {
        return plan_p2p(direct_impossible, turn);
    };
    let steps = stamped
        .upgrades()
        .filter_map(|path| match path.kind {
            PathKind::Direct => Some(step(PlanStep::Direct, path.attempt_timeout)),
            PathKind::Turn => turn
                .clone()
                .map(|cfg| step(PlanStep::Turn(cfg), path.attempt_timeout)),
            PathKind::PeerRelay | PathKind::ServerRelay => None,
        })
        .collect();
    P2pPlan {
        steps,
        turn_configured: turn.is_some(),
    }
}

#[cfg(test)]
#[path = "p2p_plan_tests.rs"]
mod tests;
