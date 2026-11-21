//! What one path attempt tries, in which order, and for how long, and why it ran. Absorbs
//! `citadel_proto`'s `p2p_plan` (the stages) and the plan half of `p2p_outcome_context` (which
//! stages a plan does not try, and why). Pure: no I/O, no clock.

use std::time::Duration;

use citadel_types::proto::{EffectivePlan, PathKind};

use crate::event::LossCause;
use crate::kind::SettingId;
use crate::path::{PathPlanKind, PathStage, StageFailure, StageOutcome};

/// The attempt timeout of each stage of a plan made without a stamped plan (the server has no
/// path policy): the hole punch with its QUIC handshake, and one relay attempt.
pub const LEGACY_DIRECT_TIMEOUT: Duration = citadel_types::proto::timing::P2P_STAGE_TIMEOUT;
pub const LEGACY_TURN_TIMEOUT: Duration = citadel_types::proto::timing::P2P_STAGE_TIMEOUT;

/// A stage and how long it may take.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimedStage {
    pub stage: PathStage,
    pub timeout: Duration,
}

/// The stages of one attempt, in order. A P2P plan's upgrade stages (Direct, Turn) are followed
/// by the server relay, which every pair has while the server is up; a C2S plan is one dial.
/// The TURN config itself stays with the adapter: the plan only says *that* TURN is tried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPlan {
    pub stages: Vec<TimedStage>,
    /// Whether this peer held a TURN config when the plan was made, for reporting why a plan
    /// without a Turn stage does not try one.
    pub turn_configured: bool,
    /// Whether both NATs are unpredictable (no punch can work), for the same report.
    pub direct_impossible: bool,
}

/// What a TURN config must say for planning. `citadel_wire`'s `TurnRelayConfig` implements it
/// in the adapter, so the policy is read from its one definition.
pub trait TurnConfig {
    /// `TurnPolicy::RelayOnly`: never punch, relay only.
    fn relay_only(&self) -> bool;
}

/// Why a path attempt ran (§6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathTrigger {
    /// The link's first establishment.
    Initial,
    /// A heal after the link was lost.
    LinkLost { cause: LossCause },
    /// The local NAT changed while the link was up.
    NatChanged,
    /// A local interface changed while the link was up.
    InterfaceChanged,
    /// A settings change needed a new seal or a new path (§4).
    SettingsChange(SettingId),
    /// The peer healed first and this side accepted its dial.
    PeerInitiated,
    /// An upgrade from the server relay to a P2P route.
    Rearm,
}

/// How the path of an establishment relates to the one before it (§6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PunchReuse {
    /// A new hole punch.
    Fresh,
    /// A fresh seal on the socket that was already punched.
    ReusedSocket,
    /// QUIC migrated the live connection to a new local socket (a rebind).
    Migrated,
    /// The existing seal on a new path (`REATTACH`).
    Reattached,
    /// No punch is involved: a C2S stream or the server relay.
    NotNeeded,
}

impl PathPlan {
    /// The C2S plan: one dial, bounded by `dial_timeout`.
    pub fn server(dial_timeout: Duration) -> Self {
        PathPlan {
            stages: vec![TimedStage {
                stage: PathStage::Dial,
                timeout: dial_timeout,
            }],
            turn_configured: false,
            direct_impossible: false,
        }
    }

    /// Whether the plan tries `stage`.
    pub fn tries(&self, stage: PathStage) -> bool {
        self.stages.iter().any(|s| s.stage == stage)
    }

    /// The stages that move a P2P link off the server relay (Direct, Turn), in order.
    pub fn upgrades(&self) -> impl Iterator<Item = (usize, &TimedStage)> {
        self.stages
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s.stage, PathStage::Direct | PathStage::Turn))
    }

    pub fn kind(&self) -> PathPlanKind {
        let upgrades: Vec<_> = self.upgrades().map(|(_, s)| s.stage).collect();
        match upgrades.as_slice() {
            _ if self.tries(PathStage::Dial) => PathPlanKind::ServerDial,
            [] => PathPlanKind::ServerOnly,
            [PathStage::Direct] => PathPlanKind::DirectOnly,
            [PathStage::Turn] => PathPlanKind::TurnOnly,
            [PathStage::Turn, PathStage::Direct] => PathPlanKind::TurnThenDirect,
            _ => PathPlanKind::DirectThenTurn,
        }
    }

    /// The P2P stages this plan does not try, each with the reason (the plan half of the
    /// protocol's `OutcomeContext`). A C2S plan skips nothing.
    pub fn not_tried(&self) -> Vec<StageOutcome> {
        let mut skipped = Vec::new();
        if self.tries(PathStage::Dial) {
            return skipped;
        }
        let not = |stage, failure| StageOutcome {
            stage,
            result: Err(failure),
            elapsed: Duration::ZERO,
        };
        if !self.tries(PathStage::Direct) {
            let why = if self.direct_impossible {
                StageFailure::NatIncompatible
            } else {
                StageFailure::SkippedByPolicy
            };
            skipped.push(not(PathStage::Direct, why));
        }
        if !self.tries(PathStage::Turn) {
            let why = if self.turn_configured {
                StageFailure::SkippedByPolicy
            } else {
                StageFailure::NotConfigured
            };
            skipped.push(not(PathStage::Turn, why));
        }
        skipped
    }
}

fn timed(stage: PathStage, timeout: Duration) -> TimedStage {
    TimedStage { stage, timeout }
}

/// The plan a peer makes alone, from its own TURN config and the (symmetric) NAT verdict: the
/// behaviour of every pair without a stamped plan. The server relay follows, within
/// `relay_timeout`.
pub fn plan_p2p<T: TurnConfig>(
    direct_impossible: bool,
    turn: Option<&T>,
    relay_timeout: Duration,
) -> PathPlan {
    let direct = || timed(PathStage::Direct, LEGACY_DIRECT_TIMEOUT);
    let turn_stage = || timed(PathStage::Turn, LEGACY_TURN_TIMEOUT);
    let mut stages = match turn {
        None if direct_impossible => vec![],
        None => vec![direct()],
        Some(cfg) if direct_impossible || cfg.relay_only() => vec![turn_stage()],
        Some(_) => vec![direct(), turn_stage()],
    };
    stages.push(timed(PathStage::Relay, relay_timeout));
    PathPlan {
        stages,
        turn_configured: turn.is_some(),
        direct_impossible,
    }
}

/// The plan for an attempt: the stamped plan's paths before the server relay, in order, each with
/// its own timeout, when the server stamped one; otherwise [`plan_p2p`]. A stamped Turn step needs
/// this peer's TURN config and is skipped without one; PeerRelay is never planned without a
/// forwarder, and none exists yet.
pub fn execution_plan<T: TurnConfig>(
    stamped: Option<&EffectivePlan>,
    direct_impossible: bool,
    turn: Option<&T>,
    relay_timeout: Duration,
) -> PathPlan {
    let Some(stamped) = stamped else {
        return plan_p2p(direct_impossible, turn, relay_timeout);
    };
    let mut stages: Vec<_> = stamped
        .upgrades()
        .filter_map(|path| match path.kind {
            PathKind::Direct => Some(timed(PathStage::Direct, path.attempt_timeout)),
            PathKind::Turn => turn.map(|_| timed(PathStage::Turn, path.attempt_timeout)),
            PathKind::PeerRelay | PathKind::ServerRelay => None,
        })
        .collect();
    stages.push(timed(PathStage::Relay, relay_timeout));
    PathPlan {
        stages,
        turn_configured: turn.is_some(),
        direct_impossible,
    }
}
