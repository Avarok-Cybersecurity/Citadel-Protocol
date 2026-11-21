//! Recording what each stage of an attempt did, and reading what it means.

use super::dispatch::since;
use super::LinkCore;
use crate::event::LossCause;
use crate::kind::Millis;
use crate::path::{PathReport, PathStage, RouteKind, StageFailure, StageOutcome};
use crate::plan::PunchReuse;

impl LinkCore {
    pub(super) fn record_coordination(&mut self, now: Millis, result: Result<(), StageFailure>) {
        if let Some(a) = self.attempt.as_mut() {
            let outcome = StageOutcome {
                stage: PathStage::Coordination,
                result,
                elapsed: since(now, a.started),
            };
            a.stages.push((outcome, std::time::Duration::ZERO));
        }
    }

    pub(super) fn record_stage(&mut self, now: Millis, result: Result<(), StageFailure>) {
        let Some(a) = self.attempt.as_mut() else {
            return;
        };
        let Some(stage) = self.plan.as_ref().and_then(|p| p.stages.get(a.stage)) else {
            return;
        };
        let outcome = StageOutcome {
            stage: stage.stage,
            result,
            elapsed: since(now, a.stage_started),
        };
        a.stages.push((outcome, since(a.stage_started, a.started)));
    }
}

/// What a stage's failure says about the link.
pub(super) fn cause_of(failure: StageFailure) -> LossCause {
    match failure {
        StageFailure::PeerOffline => LossCause::PeerOffline,
        _ => LossCause::Unreachable,
    }
}

/// What the attempt actually reused, from what it planned and what the adapter observed.
pub(super) fn observed_reuse(planned: PunchReuse, report: &PathReport, held: bool) -> PunchReuse {
    let punchless = matches!(report.kind, RouteKind::Server(_) | RouteKind::ServerRelay);
    match planned {
        PunchReuse::Reattached if held => PunchReuse::Reattached,
        _ if punchless => PunchReuse::NotNeeded,
        _ if report.reused_socket => PunchReuse::ReusedSocket,
        _ => PunchReuse::Fresh,
    }
}
