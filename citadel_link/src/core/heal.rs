//! Losing a link and healing it (§3.2 rows Up→Degraded and Degraded, §3.3, §9.3, §9.6, §9.8).

use super::{BufferMode, Heal, Held, LinkCommand, LinkCore, LinkState};
use crate::event::{CloseReason, LinkDegraded, LinkEvent, LossCause};
use crate::kind::{Incarnation, LinkKind, Millis};
use crate::plan::{PathTrigger, PunchReuse};
use crate::typestate::RetireReason;

impl LinkCore {
    /// Up → Degraded: hold sends, report once, keep the seal for a reattach (or retire it), and
    /// heal at once (the Leader) or after the fixed offset (the Loser).
    pub(super) fn degrade(
        &mut self,
        now: Millis,
        incarnation: Incarnation,
        cause: LossCause,
        out: &mut Vec<LinkCommand>,
    ) {
        self.side = None;
        self.rearm_at = None;
        self.probe_at = None;
        self.rebinding = None;
        out.push(LinkCommand::Buffer(BufferMode::Hold));
        let flapping = self.count_flap(now);
        out.push(LinkCommand::Report(LinkEvent::Degraded(LinkDegraded {
            link: self.cfg.kind,
            connection: self.cfg.connection,
            incarnation: Some(incarnation),
            cause: if flapping { LossCause::Flapping } else { cause },
            since: now,
        })));
        if self.cfg.caps.reattach && cause != LossCause::Settings {
            self.held = Some(Held {
                incarnation,
                lost_at: now,
            });
        } else {
            self.retire(incarnation, RetireReason::Lost(cause), out);
        }
        let mut next = now.after(self.cfg.policy.heal_wait(1, self.role));
        if flapping {
            next = next.max(now.after(self.cfg.policy.flap.hold));
        }
        self.state = LinkState::Degraded {
            lost_at: now,
            cause,
            attempt: 1,
            next_at: Some(next),
            paused: false,
        };
    }

    /// Records an Up→Degraded transition; whether the flap policy's hold engages.
    fn count_flap(&mut self, now: Millis) -> bool {
        let window = self.cfg.policy.flap.window;
        self.flaps.push_back(now);
        while let Some(first) = self.flaps.front() {
            if first.after(window) > now {
                break;
            }
            self.flaps.pop_front();
        }
        self.flaps.len() > self.cfg.policy.flap.max_transitions as usize
    }

    /// The wait in `Degraded` ran out: the next heal attempt, planned by `heal_plan` (§3.3).
    pub(super) fn heal_tick(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        let LinkState::Degraded {
            lost_at,
            cause,
            attempt,
            paused: false,
            ..
        } = self.state
        else {
            return;
        };
        if self.past_give_up(now, lost_at) {
            return self.give_up(now, lost_at, attempt.saturating_sub(1), out);
        }
        self.expire_held(now, cause, out);
        self.heal = Some(Heal {
            lost_at,
            cause,
            attempt,
        });
        let peer = matches!(self.cfg.kind, LinkKind::Peer { .. });
        let reattach =
            self.held.is_some() && self.cfg.caps.reattach && cause != LossCause::Settings;
        let rendezvous = peer
            && (self.plan.is_none()
                || attempt > 1
                || matches!(
                    cause,
                    LossCause::NatChanged
                        | LossCause::InterfaceChanged
                        | LossCause::PeerOffline
                        | LossCause::Settings
                ));
        let reuse = match (reattach, peer, rendezvous) {
            (true, _, _) => PunchReuse::Reattached,
            (false, false, _) => PunchReuse::NotNeeded,
            (false, true, false) => PunchReuse::ReusedSocket,
            (false, true, true) => PunchReuse::Fresh,
        };
        let trigger = self.trigger_for(cause);
        self.begin_attempt(now, trigger, reuse, Some(lost_at), rendezvous, out);
    }

    fn trigger_for(&self, cause: LossCause) -> PathTrigger {
        match (cause, self.changing) {
            (LossCause::NatChanged, _) => PathTrigger::NatChanged,
            (LossCause::InterfaceChanged, _) => PathTrigger::InterfaceChanged,
            (LossCause::Settings, Some(setting)) => PathTrigger::SettingsChange(setting),
            (cause, _) => PathTrigger::LinkLost { cause },
        }
    }

    /// A held seal past its grace can no longer be reattached: retire it.
    fn expire_held(&mut self, now: Millis, cause: LossCause, out: &mut Vec<LinkCommand>) {
        if let Some(held) = self.held {
            if now >= held.lost_at.after(self.cfg.policy.reattach_grace) {
                self.held = None;
                self.retire(held.incarnation, RetireReason::Lost(cause), out);
            }
        }
    }

    fn past_give_up(&self, now: Millis, lost_at: Millis) -> bool {
        self.cfg
            .policy
            .heal
            .give_up_after
            .is_some_and(|after| now >= lost_at.after(after))
    }

    /// An attempt of the current heal failed: wait and try again, or give up (§3.2).
    pub(super) fn heal_failed(
        &mut self,
        now: Millis,
        cause: Option<LossCause>,
        out: &mut Vec<LinkCommand>,
    ) {
        let Some(heal) = self.heal.take() else {
            return;
        };
        let exhausted = self
            .cfg
            .policy
            .heal
            .max_attempts
            .is_some_and(|max| heal.attempt >= max);
        if exhausted || self.past_give_up(now, heal.lost_at) {
            return self.give_up(now, heal.lost_at, heal.attempt, out);
        }
        let attempt = heal.attempt.saturating_add(1);
        self.state = LinkState::Degraded {
            lost_at: heal.lost_at,
            cause: cause.unwrap_or(heal.cause),
            attempt,
            next_at: Some(now.after(self.cfg.policy.heal_wait(attempt, self.role))),
            paused: false,
        };
    }

    fn give_up(&mut self, now: Millis, lost_at: Millis, attempts: u32, out: &mut Vec<LinkCommand>) {
        let reason = if self.ever_up {
            CloseReason::GaveUp {
                after: super::dispatch::since(now, lost_at),
                attempts,
            }
        } else {
            CloseReason::Unreachable { attempts }
        };
        self.close(reason, out);
    }
}
