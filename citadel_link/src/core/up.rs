//! A live link (§3.2 rows Up): a lost path, a lost direct route, a network change and its QUIC
//! rebind, the probe, and the side attempts that move a P2P link off the server relay.

use super::{LinkCommand, LinkCore, LinkState, LiveRoute};
use crate::event::LossCause;
use crate::kind::{Incarnation, LinkKind, Millis, RouteId};
use crate::path::{RouteKind, StageFailure};
use crate::plan::{PathTrigger, PunchReuse};
use crate::typestate::RetireReason;

impl LinkCore {
    pub(super) fn lost(
        &mut self,
        now: Millis,
        incarnation: Incarnation,
        cause: LossCause,
        out: &mut Vec<LinkCommand>,
    ) {
        match self.state {
            LinkState::Up {
                incarnation: live,
                route,
                since: up_since,
            } if live == incarnation => {
                let peer = matches!(self.cfg.kind, LinkKind::Peer { .. });
                if cause == LossCause::RouteLost && peer && !route.kind.is_relay() {
                    out.push(LinkCommand::FallBackToRelay);
                    let relay = LiveRoute {
                        route: RouteId::RELAY,
                        kind: RouteKind::ServerRelay,
                        migratable: false,
                    };
                    self.state = LinkState::Up {
                        incarnation,
                        route: relay,
                        since: up_since,
                    };
                    self.start_side(now, PathTrigger::LinkLost { cause }, out);
                } else {
                    let cause = match cause {
                        LossCause::RouteLost => LossCause::Transient,
                        other => other,
                    };
                    self.degrade(now, incarnation, cause, out);
                }
            }
            LinkState::Resealing { live, next, .. } if live == incarnation => {
                self.retire(next, RetireReason::Abandoned, out);
                self.changing = None;
                self.degrade(now, live, cause, out);
            }
            _ => {}
        }
    }

    pub(super) fn network_changed(
        &mut self,
        now: Millis,
        trigger: PathTrigger,
        cause: LossCause,
        out: &mut Vec<LinkCommand>,
    ) {
        let LinkState::Up {
            incarnation, route, ..
        } = self.state
        else {
            return;
        };
        if route.migratable {
            self.rebinding = Some(trigger);
            out.push(LinkCommand::Rebind { route: route.route });
        } else {
            self.degrade(now, incarnation, cause, out);
        }
    }

    pub(super) fn rebound(
        &mut self,
        now: Millis,
        rebound: RouteId,
        ok: bool,
        out: &mut Vec<LinkCommand>,
    ) {
        let LinkState::Up {
            incarnation, route, ..
        } = self.state
        else {
            return;
        };
        if route.route != rebound {
            return;
        }
        let Some(trigger) = self.rebinding.take() else {
            return;
        };
        if ok {
            let outcome = self.live_outcome(trigger, PunchReuse::Migrated, incarnation, route);
            out.push(self.report(outcome));
        } else {
            let cause = match trigger {
                PathTrigger::InterfaceChanged => LossCause::InterfaceChanged,
                _ => LossCause::NatChanged,
            };
            self.degrade(now, incarnation, cause, out);
        }
    }

    pub(super) fn up_tick(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        if let Some(side) = self.side.as_ref().filter(|s| now >= s.deadline) {
            let number = side.attempt.number;
            self.side_failed(now, number, StageFailure::Timeout, out);
        }
        if self.rearm_at.is_some_and(|at| now >= at) {
            self.rearm_at = None;
            self.start_side(now, PathTrigger::Rearm, out);
        }
        if self.probe_at.is_some_and(|at| now >= at) {
            self.probe_at = self.cfg.policy.probe_interval.map(|every| now.after(every));
            out.push(LinkCommand::Probe);
        }
    }
}
