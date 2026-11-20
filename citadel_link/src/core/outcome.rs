//! Assembling a [`PathAttemptOutcome`] (§6): from an attempt's stages and the plan's untried
//! stages, or, for an establishment that ran no stage (a rebind, a reseal), from the live route.

use std::time::Duration;

use super::dispatch::since;
use super::{Attempt, LinkCommand, LinkCore, LiveRoute};
use crate::event::{LinkEvent, PathAttemptOutcome};
use crate::kind::{Incarnation, LinkKind, Millis};
use crate::path::PathPlanKind;
use crate::plan::{PathTrigger, PunchReuse};

impl LinkCore {
    pub(super) fn report(&self, outcome: PathAttemptOutcome) -> LinkCommand {
        LinkCommand::Report(LinkEvent::Path(outcome))
    }

    fn plan_kind(&self) -> PathPlanKind {
        match (&self.plan, self.cfg.kind) {
            (Some(plan), _) => plan.kind(),
            (None, LinkKind::Server) => PathPlanKind::ServerDial,
            (None, LinkKind::Peer { .. }) => PathPlanKind::ServerOnly,
        }
    }

    /// The outcome of `a`; `attached` when it established the link.
    pub(super) fn outcome(&self, a: &Attempt, attached: bool, now: Millis) -> PathAttemptOutcome {
        let mut runs = a.stages.clone();
        let used_plan = runs.iter().any(|(s, _)| self.plan_stage(s.stage));
        if let Some(plan) = self.plan.as_ref().filter(|_| used_plan) {
            runs.extend(plan.not_tried().into_iter().map(|s| (s, Duration::ZERO)));
        }
        runs.sort_by_key(|(s, _)| s.stage);
        let report = a.opened.as_ref().filter(|_| attached);
        PathAttemptOutcome {
            peer_cid: self.cfg.kind.reported_cid(),
            attempt: a.number,
            plan: self.plan_kind(),
            path: report.map(|r| r.kind),
            stages: runs.iter().map(|(s, _)| *s).collect(),
            local_nat: self.local_nat,
            peer_nat: a.opened.as_ref().and_then(|r| r.peer_nat),
            link: self.cfg.kind,
            trigger: a.trigger,
            punch: a.reuse,
            incarnation: attached.then_some(a.incarnation),
            route_id: report.map(|r| r.route),
            downtime: a.down_since.map(|d| since(now, d)),
            stage_started_at: runs.iter().map(|(_, at)| *at).collect(),
        }
    }

    fn plan_stage(&self, stage: crate::path::PathStage) -> bool {
        self.plan.as_ref().is_some_and(|p| p.tries(stage))
    }

    /// An establishment on the live route that ran no stage: a QUIC rebind or a reseal.
    pub(super) fn live_outcome(
        &mut self,
        trigger: PathTrigger,
        punch: PunchReuse,
        incarnation: Incarnation,
        route: LiveRoute,
    ) -> PathAttemptOutcome {
        self.attempts = self.attempts.saturating_add(1);
        PathAttemptOutcome {
            peer_cid: self.cfg.kind.reported_cid(),
            attempt: self.attempts,
            plan: self.plan_kind(),
            path: Some(route.kind),
            stages: Vec::new(),
            local_nat: self.local_nat,
            peer_nat: None,
            link: self.cfg.kind,
            trigger,
            punch,
            incarnation: Some(incarnation),
            route_id: Some(route.route),
            downtime: None,
            stage_started_at: Vec::new(),
        }
    }
}
