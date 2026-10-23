//! Assembling a [`PathAttemptOutcome`] from what a connection's plan does not try and what an
//! attempt ran. Pure: no I/O, no clock.

use std::time::Duration;

use citadel_wire::nat_class::NatClass;

use super::p2p_outcome::{
    AttemptReport, PathAttemptOutcome, PathPlanKind, PathStage, StageFailure, StageOutcome,
};
use super::p2p_path::{P2pPath, P2pRoute};
use super::p2p_plan::P2pPlan;

/// Everything about a connection's attempts that does not change between them.
#[derive(Clone)]
pub(crate) struct OutcomeContext {
    pub(crate) peer_cid: u64,
    pub(crate) plan: PathPlanKind,
    /// The stages the plan does not try, with the reason.
    pub(crate) not_tried: Vec<StageOutcome>,
    pub(crate) local_nat: NatClass,
    pub(crate) peer_nat: NatClass,
}

impl OutcomeContext {
    pub(crate) fn new(
        peer_cid: u64,
        plan: &P2pPlan,
        direct_impossible: bool,
        local_nat: NatClass,
        peer_nat: NatClass,
    ) -> Self {
        let (kind, not_tried) = plan_stages(plan, direct_impossible);
        Self {
            peer_cid,
            plan: kind,
            not_tried,
            local_nat,
            peer_nat,
        }
    }

    /// The outcome of attempt `attempt`, whose coordination took `coordination` and whose
    /// platform attempt reported `report`.
    pub(crate) fn outcome(
        &self,
        attempt: u32,
        coordination: Duration,
        report: AttemptReport,
    ) -> PathAttemptOutcome {
        let mut stages = vec![tried(PathStage::Coordination, Ok(()), coordination)];
        stages.extend(self.not_tried.iter().copied());
        stages.extend(report.stages);
        stages.sort_by_key(|s| s.stage);
        let (path, relayed_both) = match report.route {
            Some(P2pRoute::Direct) => (P2pPath::Direct, false),
            Some(P2pRoute::Turn { relayed_both }) => (P2pPath::Turn, relayed_both),
            None => (P2pPath::ServerRelay, false),
        };
        PathAttemptOutcome {
            peer_cid: self.peer_cid,
            attempt,
            plan: self.plan,
            path,
            relayed_both,
            stages,
            local_nat: self.local_nat,
            peer_nat: self.peer_nat,
        }
    }

    /// The outcome of an attempt that never reached a punch: the peers did not meet.
    pub(crate) fn unmet(
        &self,
        attempt: u32,
        failure: StageFailure,
        elapsed: Duration,
    ) -> PathAttemptOutcome {
        let mut outcome = self.outcome(attempt, elapsed, AttemptReport::nothing_attached(vec![]));
        outcome
            .stages
            .retain(|s| s.stage == PathStage::Coordination);
        outcome.stages[0].result = Err(failure);
        outcome
    }
}

pub(crate) fn tried(
    stage: PathStage,
    result: Result<(), StageFailure>,
    elapsed: Duration,
) -> StageOutcome {
    StageOutcome {
        stage,
        result,
        elapsed,
    }
}

/// The plan's kind, and the stages it does not try with the reason for each.
fn plan_stages(plan: &P2pPlan, direct_impossible: bool) -> (PathPlanKind, Vec<StageOutcome>) {
    let skipped = |stage, why| tried(stage, Err(why), Duration::ZERO);
    let mut not_tried = Vec::new();
    if !plan.tries(PathStage::Direct) {
        let why = if direct_impossible {
            StageFailure::NatIncompatible
        } else {
            StageFailure::SkippedByPolicy
        };
        not_tried.push(skipped(PathStage::Direct, why));
    }
    if !plan.tries(PathStage::Turn) {
        let why = if plan.turn_configured {
            StageFailure::SkippedByPolicy
        } else {
            StageFailure::NotConfigured
        };
        not_tried.push(skipped(PathStage::Turn, why));
    }
    (plan.kind(), not_tried)
}
