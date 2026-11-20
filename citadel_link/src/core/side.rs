//! Side attempts on a live link: moving it off the server relay onto a P2P route under the live
//! seal (the campaign's re-arm, §3.2 row Up+RouteLost, §9.7).

use super::dispatch::since;
use super::{Attempt, LinkCommand, LinkCore, LinkState, LiveRoute, Side};
use crate::kind::Millis;
use crate::path::{PathReport, StageFailure, StageOutcome};
use crate::plan::{PathTrigger, PunchReuse};

impl LinkCore {
    /// Starts a side attempt at the plan's first upgrade stage, under the live seal.
    pub(super) fn start_side(
        &mut self,
        now: Millis,
        trigger: PathTrigger,
        out: &mut Vec<LinkCommand>,
    ) {
        let LinkState::Up { incarnation, .. } = self.state else {
            return;
        };
        let first = self
            .plan
            .as_ref()
            .and_then(|p| p.upgrades().next().map(|(i, _)| i));
        let Some(first) = first else {
            return;
        };
        self.attempts = self.attempts.saturating_add(1);
        let attempt = Attempt {
            number: self.attempts,
            trigger,
            reuse: PunchReuse::Fresh,
            started: now,
            stages: Vec::new(),
            down_since: None,
            incarnation,
            opened: None,
            stage: first,
            stage_started: now,
        };
        self.side_stage(now, attempt, first, out);
    }

    fn side_stage(
        &mut self,
        now: Millis,
        mut attempt: Attempt,
        index: usize,
        out: &mut Vec<LinkCommand>,
    ) {
        let Some(stage) = self
            .plan
            .as_ref()
            .and_then(|p| p.stages.get(index))
            .copied()
        else {
            return;
        };
        attempt.stage = index;
        attempt.stage_started = now;
        let deadline = now.after(stage.timeout);
        out.push(LinkCommand::OpenPath {
            attempt: attempt.number,
            stage,
            trigger: attempt.trigger,
            reuse: attempt.reuse,
            deadline,
        });
        self.side = Some(Side { attempt, deadline });
    }

    fn side_record(&mut self, now: Millis, result: Result<(), StageFailure>) -> Option<Attempt> {
        let mut side = self.side.take()?;
        let stage = self.plan.as_ref()?.stages.get(side.attempt.stage)?.stage;
        let a = &mut side.attempt;
        let outcome = StageOutcome {
            stage,
            result,
            elapsed: since(now, a.stage_started),
        };
        a.stages.push((outcome, since(a.stage_started, a.started)));
        Some(side.attempt)
    }

    pub(super) fn side_opened(
        &mut self,
        now: Millis,
        attempt: u32,
        report: PathReport,
        out: &mut Vec<LinkCommand>,
    ) {
        if self.side.as_ref().map(|s| s.attempt.number) != Some(attempt) {
            return;
        }
        let LinkState::Up {
            incarnation,
            since: up_since,
            ..
        } = self.state
        else {
            return;
        };
        let Some(mut a) = self.side_record(now, Ok(())) else {
            return;
        };
        let route = LiveRoute {
            route: report.route,
            kind: report.kind,
            migratable: report.migratable,
        };
        a.opened = Some(report);
        out.push(LinkCommand::AttachRoute { route: route.route });
        out.push(self.report(self.outcome(&a, true, now)));
        self.rearm_failures = 0;
        self.rearm_at = None;
        self.state = LinkState::Up {
            incarnation,
            route,
            since: up_since,
        };
    }

    pub(super) fn side_failed(
        &mut self,
        now: Millis,
        attempt: u32,
        failure: StageFailure,
        out: &mut Vec<LinkCommand>,
    ) {
        if self.side.as_ref().map(|s| s.attempt.number) != Some(attempt) {
            return;
        }
        let Some(a) = self.side_record(now, Err(failure)) else {
            return;
        };
        let next = self
            .plan
            .as_ref()
            .and_then(|p| p.upgrades().map(|(i, _)| i).find(|i| *i > a.stage));
        if let Some(next) = next {
            return self.side_stage(now, a, next, out);
        }
        out.push(self.report(self.outcome(&a, false, now)));
        self.rearm_failures = self.rearm_failures.saturating_add(1);
        self.rearm_at = Some(now.after(self.cfg.policy.rearm.wait(self.rearm_failures)));
    }
}
