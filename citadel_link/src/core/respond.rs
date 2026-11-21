//! The inputs a degraded link answers besides its own timer: suspension, probes, a peer coming
//! online, and a peer that healed first (§9.6, §9.8, §5.4).

use super::{Attempt, Heal, LinkCommand, LinkCore, LinkState};
use crate::event::LossCause;
use crate::kind::{Incarnation, LinkKind, Millis, Role};
use crate::path::PathReport;
use crate::plan::{PathTrigger, PunchReuse};

impl LinkCore {
    pub(super) fn suspended(&mut self) {
        if let LinkState::Degraded {
            paused, next_at, ..
        } = &mut self.state
        {
            *paused = true;
            *next_at = None;
        }
    }

    /// Resumed: probe at once; the probe's answer decides when to heal. The attempt counter
    /// starts again: the time asleep was not a failed heal.
    pub(super) fn resumed(&mut self, out: &mut Vec<LinkCommand>) {
        if let LinkState::Degraded {
            paused: paused @ true,
            attempt,
            next_at,
            ..
        } = &mut self.state
        {
            *paused = false;
            *attempt = 1;
            *next_at = None;
            out.push(LinkCommand::Probe);
        }
    }

    pub(super) fn probe_result(&mut self, now: Millis, ok: bool, out: &mut Vec<LinkCommand>) {
        let role = self.role;
        let policy = self.cfg.policy;
        match &mut self.state {
            LinkState::Degraded {
                paused: false,
                next_at: next_at @ None,
                attempt,
                ..
            } => {
                let wait = if ok {
                    std::time::Duration::ZERO
                } else {
                    policy.heal_wait(*attempt + 1, role)
                };
                *next_at = Some(now.after(wait));
            }
            LinkState::Up { incarnation, .. } if !ok => {
                let incarnation = *incarnation;
                self.degrade(now, incarnation, LossCause::Transient, out);
            }
            _ => {}
        }
    }

    /// The peer came online: heal now instead of waiting out the backoff (§9.6).
    pub(super) fn peer_reachable(&mut self, now: Millis) {
        if let LinkState::Degraded {
            paused: false,
            next_at: next_at @ Some(_),
            ..
        } = &mut self.state
        {
            *next_at = Some(now);
        }
    }

    /// The peer healed first and dialled this side: seal as the responder, deterministically
    /// (the Loser accepts while it waits its offset, §5.4). An offer naming the seal this side
    /// holds is a reattach: the responder verifies it against its own copy (§5.2).
    pub(super) fn peer_offer(
        &mut self,
        now: Millis,
        incarnation: Incarnation,
        report: PathReport,
        out: &mut Vec<LinkCommand>,
    ) {
        self.half_open(now, incarnation, out);
        let mid_attempt = self.role == Role::Loser
            && matches!(
                self.state,
                LinkState::Resolving { .. } | LinkState::Opening { .. }
            );
        let waiting = match self.state {
            LinkState::Degraded {
                paused: false,
                lost_at,
                cause,
                attempt,
                ..
            } => Some(Heal {
                lost_at,
                cause,
                attempt,
            }),
            _ if mid_attempt => self.heal,
            _ => None,
        };
        let reattach = self.held.is_some_and(|h| h.incarnation == incarnation);
        let fresh = self.issued.is_none_or(|issued| incarnation > issued);
        let (Some(heal), LinkKind::Peer { .. }, true) = (waiting, self.cfg.kind, fresh || reattach)
        else {
            return;
        };
        if mid_attempt {
            out.push(LinkCommand::ClosePath);
        }
        self.heal = Some(heal);
        self.attempts = self.attempts.saturating_add(1);
        let reuse = match (reattach, report.reused_socket) {
            (true, _) => PunchReuse::Reattached,
            (false, true) => PunchReuse::ReusedSocket,
            (false, false) => PunchReuse::Fresh,
        };
        self.attempt = Some(Attempt {
            number: self.attempts,
            // The first establishment is `Initial` on both ends, whoever's handshake won (§6.2).
            trigger: if self.ever_up {
                PathTrigger::PeerInitiated
            } else {
                PathTrigger::Initial
            },
            reuse,
            started: now,
            stages: Vec::new(),
            down_since: self.ever_up.then_some(heal.lost_at),
            incarnation,
            opened: Some(report),
            stage: 0,
            stage_started: now,
        });
        let deadline = now.after(self.cfg.policy.seal_deadline);
        if reattach {
            self.state = LinkState::Reattaching {
                attempt: self.attempts,
                incarnation,
                deadline,
            };
            return out.push(LinkCommand::Reattach {
                incarnation,
                deadline,
            });
        }
        self.issued = Some(incarnation);
        self.state = LinkState::Sealing {
            attempt: self.attempts,
            incarnation,
            deadline,
        };
        out.push(LinkCommand::Seal {
            incarnation,
            params: crate::decision::SealParams {
                settings: self.settings,
            },
            deadline,
        });
    }

    /// An offer while this side is still up means the peer saw a drop this side did not (a
    /// half-open link): the live path is lost here too, so degrade first, then answer the offer.
    fn half_open(&mut self, now: Millis, offered: Incarnation, out: &mut Vec<LinkCommand>) {
        let LinkState::Up { incarnation, .. } = self.state else {
            return;
        };
        let peer = matches!(self.cfg.kind, LinkKind::Peer { .. });
        let newer = self.issued.is_none_or(|issued| offered > issued);
        if peer && (offered == incarnation || newer) {
            self.degrade(now, incarnation, LossCause::Transient, out);
        }
    }
}
