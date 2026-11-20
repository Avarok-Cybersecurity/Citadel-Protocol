//! A seal finishing or failing (§3.2 rows Sealing, Reattaching), the move to `Up`, and
//! retirement bookkeeping.

use super::{BufferMode, LinkCommand, LinkCore, LinkState, LiveRoute};
use crate::event::{CloseReason, LossCause};
use crate::kind::{Incarnation, LinkKind, Millis};
use crate::plan::PunchReuse;
use crate::typestate::{RetireReason, SealFailure};

impl LinkCore {
    pub(super) fn sealed(
        &mut self,
        now: Millis,
        incarnation: Incarnation,
        out: &mut Vec<LinkCommand>,
    ) {
        match self.state {
            LinkState::Sealing { incarnation: i, .. }
            | LinkState::Reattaching { incarnation: i, .. }
                if i == incarnation =>
            {
                self.become_up(now, incarnation, out)
            }
            LinkState::Resealing { next, .. } if next == incarnation => self.cut_over(now, out),
            _ => {}
        }
    }

    fn become_up(&mut self, now: Millis, incarnation: Incarnation, out: &mut Vec<LinkCommand>) {
        let Some(mut a) = self.attempt.take() else {
            return;
        };
        let Some(report) = a.opened.clone() else {
            return;
        };
        let reattached = a.reuse == PunchReuse::Reattached
            && self.held.is_some_and(|h| h.incarnation == incarnation);
        if let Some(held) = self.held.take().filter(|_| !reattached) {
            self.retire(held.incarnation, RetireReason::Superseded, out);
        }
        if !reattached {
            self.sealed_count = self.sealed_count.saturating_add(1);
            self.live.push(incarnation);
        }
        a.incarnation = incarnation;
        let route = LiveRoute {
            route: report.route,
            kind: report.kind,
            migratable: report.migratable,
        };
        out.push(LinkCommand::Deliver { incarnation });
        out.push(LinkCommand::Buffer(BufferMode::Live));
        out.push(self.report(self.outcome(&a, true, now)));
        self.ever_up = true;
        self.heal = None;
        self.changing = None;
        self.state = LinkState::Up {
            incarnation,
            route,
            since: now,
        };
        self.arm_live_timers(now, route);
    }

    /// The live link's own timers: the probe, and the re-arm that moves a P2P link off the relay.
    pub(super) fn arm_live_timers(&mut self, now: Millis, route: LiveRoute) {
        self.probe_at = self.cfg.policy.probe_interval.map(|every| now.after(every));
        let upgradable = matches!(self.cfg.kind, LinkKind::Peer { .. })
            && route.kind.is_relay()
            && self
                .plan
                .as_ref()
                .is_some_and(|p| p.upgrades().next().is_some());
        self.rearm_at =
            upgradable.then(|| now.after(self.cfg.policy.rearm.wait(self.rearm_failures)));
    }

    pub(super) fn seal_failed(
        &mut self,
        now: Millis,
        incarnation: Incarnation,
        failure: SealFailure,
        out: &mut Vec<LinkCommand>,
    ) {
        match self.state {
            LinkState::Sealing { incarnation: i, .. }
            | LinkState::Reattaching { incarnation: i, .. }
                if i != incarnation => {}
            LinkState::Resealing { next, .. } if next == incarnation => {
                self.reseal_failed(now, out)
            }
            LinkState::Sealing { .. } | LinkState::Reattaching { .. } => match failure {
                SealFailure::Refused(refusal) => {
                    self.attempt = None;
                    self.close(CloseReason::Refused(refusal), out);
                }
                SealFailure::UnknownSeal if matches!(self.state, LinkState::Reattaching { .. }) => {
                    self.reattach_refused(now, out)
                }
                _ => {
                    out.push(LinkCommand::ClosePath);
                    self.attempt_failed(now, None, out);
                }
            },
            _ => {}
        }
    }

    /// The far end no longer holds the seal: a fresh seal on the path already open, no new
    /// punch (§3.2, §5.2).
    fn reattach_refused(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        if let Some(held) = self.held.take() {
            let cause = self.heal.map_or(LossCause::Transient, |h| h.cause);
            self.retire(held.incarnation, RetireReason::Lost(cause), out);
        }
        let Some(a) = self.attempt.as_mut() else {
            return;
        };
        a.reuse = match &a.opened {
            Some(r) if matches!(r.kind, crate::path::RouteKind::Server(_)) => PunchReuse::NotNeeded,
            Some(r) if r.reused_socket => PunchReuse::ReusedSocket,
            _ => PunchReuse::Fresh,
        };
        let attempt = a.number;
        let deadline = now.after(self.cfg.policy.seal_deadline);
        self.fresh_seal(attempt, deadline, out);
    }

    /// Retires a delivered incarnation (or an abandoned one); its answer is awaited on close.
    pub(super) fn retire(
        &mut self,
        incarnation: Incarnation,
        reason: RetireReason,
        out: &mut Vec<LinkCommand>,
    ) {
        self.live.retain(|i| *i != incarnation);
        if !self.retiring.contains(&incarnation) {
            self.retiring.push(incarnation);
        }
        out.push(LinkCommand::Retire {
            incarnation,
            reason,
        });
    }
}
