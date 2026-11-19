//! How the world answers each port call (§11.1): the rendezvous needs the server and a live
//! peer, a stage needs its network, a handshake is one exchange both ends see, and a reattach
//! needs the far end to still hold the seal.

use super::{Op, Side, World};
use crate::core::LinkInput;
use crate::kind::{Incarnation, RouteId};
use crate::path::{NatClass, PathReport, PathStage, RouteKind, ServerTransport, StageFailure};
use crate::plan::{PunchReuse, TimedStage};
use crate::typestate::{PathFailure, SealFailure};
use crate::LinkState;

impl World {
    pub(super) fn resolve(&mut self, side: Side, i: usize, ok: bool) {
        let Some(op) = self.party(side).ops.get(i).copied() else {
            return;
        };
        self.party_mut(side).ops.remove(i);
        if !ok {
            self.server_needed = true;
        }
        match op {
            Op::Meet { attempt } => {
                let peer_alive = !matches!(
                    self.state(side.other()),
                    LinkState::Closed { .. } | LinkState::Dormant
                );
                let met = ok && self.net.server_up && peer_alive;
                if met {
                    self.meet_other(side.other());
                }
                let input = if met {
                    LinkInput::Met {
                        attempt,
                        plan: self.net.plan.clone(),
                    }
                } else {
                    let failure = if self.net.server_up {
                        StageFailure::PeerOffline
                    } else {
                        StageFailure::Unreachable
                    };
                    LinkInput::MeetFailed { attempt, failure }
                };
                self.step(side, input)
            }
            Op::Open {
                attempt,
                stage,
                reuse,
            } => self.open(side, attempt, stage, reuse, ok),
            Op::Seal { incarnation } => self.handshake(side, incarnation, ok, false),
            Op::Reattach { incarnation } => self.handshake(side, incarnation, ok, true),
            Op::Retire { incarnation } => self.step(side, LinkInput::Retired { incarnation }),
            Op::Probe => {
                let ok = ok && self.net.server_up;
                self.step(side, LinkInput::ProbeResult { ok })
            }
            Op::Rebind { route } => {
                let ok = ok && self.net.rebind_works;
                self.step(side, LinkInput::Rebound { route, ok })
            }
        }
    }

    /// A rendezvous is one exchange: a far end that is meeting too meets now, with the same plan.
    fn meet_other(&mut self, other: Side) {
        let pending = self
            .party(other)
            .ops
            .iter()
            .position(|op| matches!(op, Op::Meet { .. }));
        if let Some(j) = pending {
            if let Op::Meet { attempt } = self.party_mut(other).ops.remove(j) {
                let plan = self.net.plan.clone();
                self.step(other, LinkInput::Met { attempt, plan });
            }
        }
    }

    fn stage_works(&self, stage: PathStage) -> bool {
        match stage {
            PathStage::Direct => self.net.direct_works,
            PathStage::Turn => self.net.turn_works,
            PathStage::Relay | PathStage::Dial | PathStage::Coordination => self.net.server_up,
        }
    }

    pub(super) fn path_report(
        &mut self,
        side: Side,
        stage: PathStage,
        reuse: PunchReuse,
    ) -> PathReport {
        let kind = match stage {
            PathStage::Direct => RouteKind::Direct,
            PathStage::Turn => RouteKind::Turn {
                relayed_both: false,
            },
            PathStage::Dial => RouteKind::Server(ServerTransport::Tcp),
            PathStage::Relay | PathStage::Coordination => RouteKind::ServerRelay,
        };
        let route = if kind.is_relay() {
            RouteId::RELAY
        } else {
            self.next_route += 1;
            RouteId(self.next_route)
        };
        let local_nat = self.party(side).core.config().local_nat;
        PathReport {
            kind,
            route,
            migratable: kind == RouteKind::Direct && side == Side::A,
            extra_stages: Vec::new(),
            reused_socket: reuse == PunchReuse::ReusedSocket && stage == PathStage::Direct,
            local_nat,
            peer_nat: Some(nat_of(&self.party(side.other()).core)),
        }
    }

    fn open(&mut self, side: Side, attempt: u32, stage: TimedStage, reuse: PunchReuse, ok: bool) {
        let input = if ok && self.stage_works(stage.stage) {
            LinkInput::PathOpened {
                attempt,
                report: self.path_report(side, stage.stage, reuse),
            }
        } else {
            let failure = match stage.stage {
                PathStage::Direct => StageFailure::PunchFailed,
                PathStage::Turn => StageFailure::AllocationFailed,
                _ => StageFailure::Unreachable,
            };
            LinkInput::PathFailed {
                attempt,
                failure: PathFailure {
                    stage: stage.stage,
                    failure,
                },
            }
        };
        self.step(side, input)
    }

    /// One handshake, seen by both ends. The far end answers from what it holds: a matching op,
    /// a Loser's reseal (it seals as the responder), or a peer that is waiting to be dialled
    /// (`PeerOffer`).
    fn handshake(&mut self, side: Side, incarnation: Incarnation, ok: bool, reattach: bool) {
        let other = side.other();
        let pending = |w: &World| {
            w.party(other).ops.iter().position(|op| match op {
                Op::Seal { incarnation: i } => !reattach && *i == incarnation,
                Op::Reattach { incarnation: i } => reattach && *i == incarnation,
                _ => false,
            })
        };
        let loser_resealing =
            matches!(self.state(other), LinkState::Resealing { next, .. } if *next == incarnation);
        if ok && pending(self).is_none() && !loser_resealing {
            let report = self.party_report(other);
            self.step(
                other,
                LinkInput::PeerOffer {
                    incarnation,
                    report,
                },
            );
        }
        match pending(self) {
            Some(j) if ok => {
                self.party_mut(other).ops.remove(j);
                self.step(side, LinkInput::Sealed { incarnation });
                self.step(other, LinkInput::Sealed { incarnation });
            }
            None if ok && loser_resealing => {
                self.step(side, LinkInput::Sealed { incarnation });
                self.step(other, LinkInput::Sealed { incarnation });
            }
            _ => {
                let failure = match (ok, reattach) {
                    (true, true) => SealFailure::UnknownSeal,
                    (true, false) => SealFailure::Handshake,
                    (false, _) => SealFailure::Timeout,
                };
                self.step(
                    side,
                    LinkInput::SealFailed {
                        incarnation,
                        failure,
                    },
                );
            }
        }
    }

    /// The path the far end sees for an incoming handshake: the one the dialling side opened.
    fn party_report(&mut self, side: Side) -> PathReport {
        let stage = match self.net.direct_works {
            true => PathStage::Direct,
            false => PathStage::Relay,
        };
        self.path_report(side, stage, PunchReuse::Fresh)
    }
}

fn nat_of(core: &crate::LinkCore) -> NatClass {
    core.config().local_nat
}
