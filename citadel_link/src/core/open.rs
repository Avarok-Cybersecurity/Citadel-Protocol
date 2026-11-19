//! Starting an attempt and stepping it through its rendezvous and its path stages (§3.2 rows
//! Dormant, Resolving, Opening).

use super::dispatch::since;
use super::stages::{cause_of, observed_reuse};
use super::{Attempt, Heal, LinkCommand, LinkCore, LinkState, RendezvousVia};
use crate::decision::SealParams;
use crate::event::LossCause;
use crate::kind::{Incarnation, LinkKind, Millis};
use crate::path::{PathReport, StageFailure};
use crate::plan::{PathPlan, PathTrigger, PunchReuse};

impl LinkCore {
    pub(super) fn start(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        if self.state != LinkState::Dormant {
            return;
        }
        self.heal = Some(Heal {
            lost_at: now,
            cause: LossCause::Unreachable,
            attempt: 1,
        });
        let peer = matches!(self.cfg.kind, LinkKind::Peer { .. });
        let reuse = if peer {
            PunchReuse::Fresh
        } else {
            PunchReuse::NotNeeded
        };
        self.begin_attempt(now, PathTrigger::Initial, reuse, None, peer, out);
    }

    /// The incarnation a fresh seal takes next.
    pub(super) fn next_incarnation(&self) -> Incarnation {
        match self.issued {
            None => Incarnation::first(self.cfg.connection),
            Some(last) => last.next().unwrap_or(last),
        }
    }

    pub(super) fn begin_attempt(
        &mut self,
        now: Millis,
        trigger: PathTrigger,
        reuse: PunchReuse,
        down_since: Option<Millis>,
        rendezvous: bool,
        out: &mut Vec<LinkCommand>,
    ) {
        self.attempts = self.attempts.saturating_add(1);
        self.attempt = Some(Attempt {
            number: self.attempts,
            trigger,
            reuse,
            started: now,
            stages: Vec::new(),
            down_since,
            incarnation: self.next_incarnation(),
            opened: None,
            stage: 0,
            stage_started: now,
        });
        if rendezvous {
            let deadline = now.after(self.cfg.policy.rendezvous_deadline);
            self.state = LinkState::Resolving {
                attempt: self.attempts,
                deadline,
            };
            out.push(LinkCommand::Rendezvous {
                attempt: self.attempts,
                via: RendezvousVia::Server,
                deadline,
            });
        } else {
            self.open_stage(now, 0, out);
        }
    }

    fn open_stage(&mut self, now: Millis, index: usize, out: &mut Vec<LinkCommand>) {
        let stage = self
            .plan
            .as_ref()
            .and_then(|p| p.stages.get(index))
            .copied();
        let (Some(stage), Some(attempt)) = (stage, self.attempt.as_mut()) else {
            return self.attempt_failed(now, Some(LossCause::Unreachable), out);
        };
        attempt.stage = index;
        attempt.stage_started = now;
        let deadline = now.after(stage.timeout);
        self.state = LinkState::Opening {
            attempt: attempt.number,
            stage: index,
            deadline,
        };
        out.push(LinkCommand::OpenPath {
            attempt: attempt.number,
            stage,
            trigger: attempt.trigger,
            reuse: attempt.reuse,
            deadline,
        });
    }

    fn current_attempt(&self, number: u32) -> bool {
        self.attempt.as_ref().map(|a| a.number) == Some(number)
    }

    pub(super) fn met(
        &mut self,
        now: Millis,
        attempt: u32,
        plan: PathPlan,
        out: &mut Vec<LinkCommand>,
    ) {
        if !matches!(self.state, LinkState::Resolving { .. }) || !self.current_attempt(attempt) {
            return;
        }
        self.record_coordination(now, Ok(()));
        self.plan = Some(plan);
        self.open_stage(now, 0, out);
    }

    pub(super) fn meet_failed(
        &mut self,
        now: Millis,
        attempt: u32,
        failure: StageFailure,
        out: &mut Vec<LinkCommand>,
    ) {
        if !matches!(self.state, LinkState::Resolving { .. }) || !self.current_attempt(attempt) {
            return;
        }
        self.record_coordination(now, Err(failure));
        self.attempt_failed(now, Some(cause_of(failure)), out);
    }

    pub(super) fn path_opened(
        &mut self,
        now: Millis,
        attempt: u32,
        report: PathReport,
        out: &mut Vec<LinkCommand>,
    ) {
        if !matches!(self.state, LinkState::Opening { .. }) || !self.current_attempt(attempt) {
            return self.side_opened(now, attempt, report, out);
        }
        self.record_stage(now, Ok(()));
        self.local_nat = report.local_nat;
        let held = self.held;
        let deadline = now.after(self.cfg.policy.seal_deadline);
        let Some(a) = self.attempt.as_mut() else {
            return;
        };
        a.stages.extend(
            report
                .extra_stages
                .iter()
                .map(|s| (*s, since(now, a.started))),
        );
        a.reuse = observed_reuse(a.reuse, &report, held.is_some());
        a.opened = Some(report);
        match held.filter(|_| a.reuse == PunchReuse::Reattached) {
            Some(held) => {
                a.incarnation = held.incarnation;
                self.state = LinkState::Reattaching {
                    attempt,
                    incarnation: held.incarnation,
                    deadline,
                };
                out.push(LinkCommand::Reattach {
                    incarnation: held.incarnation,
                    deadline,
                });
            }
            None => self.fresh_seal(attempt, deadline, out),
        }
    }

    /// A fresh handshake on the path the current attempt opened.
    pub(super) fn fresh_seal(
        &mut self,
        attempt: u32,
        deadline: Millis,
        out: &mut Vec<LinkCommand>,
    ) {
        let incarnation = self.next_incarnation();
        self.issued = Some(incarnation);
        if let Some(a) = self.attempt.as_mut() {
            a.incarnation = incarnation;
        }
        self.state = LinkState::Sealing {
            attempt,
            incarnation,
            deadline,
        };
        out.push(LinkCommand::Seal {
            incarnation,
            params: SealParams {
                settings: self.settings,
            },
            deadline,
        });
    }

    pub(super) fn path_failed(
        &mut self,
        now: Millis,
        attempt: u32,
        failure: StageFailure,
        out: &mut Vec<LinkCommand>,
    ) {
        let LinkState::Opening { stage, .. } = self.state else {
            return self.side_failed(now, attempt, failure, out);
        };
        if !self.current_attempt(attempt) {
            return self.side_failed(now, attempt, failure, out);
        }
        self.record_stage(now, Err(failure));
        let stages = self.plan.as_ref().map_or(0, |p| p.stages.len());
        if stage + 1 < stages {
            self.open_stage(now, stage + 1, out);
        } else {
            self.attempt_failed(now, Some(cause_of(failure)), out);
        }
    }

    /// The attempt ended without an establishment: its outcome, then back to healing.
    pub(super) fn attempt_failed(
        &mut self,
        now: Millis,
        cause: Option<LossCause>,
        out: &mut Vec<LinkCommand>,
    ) {
        if let Some(a) = self.attempt.take() {
            out.push(self.report(self.outcome(&a, false, now)));
        }
        self.heal_failed(now, cause, out);
    }
}
