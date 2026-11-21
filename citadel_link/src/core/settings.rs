//! A settings change on a live link (§3.2 rows Up+SettingsAgreed and Resealing, §4).

use super::{LinkCommand, LinkCore, LinkState};
use crate::decision::{decide, LinkSettings, SettingsDecision};
use crate::event::LossCause;
use crate::kind::{Epoch, Millis, Role, SettingId};
use crate::plan::{PathTrigger, PunchReuse};
use crate::typestate::RetireReason;

impl LinkCore {
    pub(super) fn settings_agreed(
        &mut self,
        now: Millis,
        epoch: Epoch,
        setting: SettingId,
        agreed: LinkSettings,
        out: &mut Vec<LinkCommand>,
    ) {
        let LinkState::Up {
            incarnation, route, ..
        } = self.state
        else {
            return;
        };
        match decide(&self.settings, &agreed, self.cfg.caps) {
            SettingsDecision::NoAction
            | SettingsDecision::LocalOnly { .. }
            | SettingsDecision::InBandKeyEpoch(_) => self.settings = agreed,
            SettingsDecision::ResealOnPath(params) => {
                let next = self.next_incarnation();
                self.issued = Some(next);
                self.changing = Some(setting);
                let deadline = now.after(self.cfg.policy.settings_deadline);
                if self.role == Role::Leader {
                    out.push(LinkCommand::ForkPath {
                        live: incarnation,
                        next,
                    });
                    out.push(LinkCommand::Seal {
                        incarnation: next,
                        params,
                        deadline,
                    });
                }
                self.state = LinkState::Resealing {
                    live: incarnation,
                    route,
                    next,
                    epoch,
                    params,
                    deadline,
                };
            }
            SettingsDecision::Reestablish { .. } => {
                self.settings = agreed;
                self.changing = Some(setting);
                self.degrade(now, incarnation, LossCause::Settings, out);
            }
        }
    }

    /// The new incarnation is sealed on the live path: both ends switch at the cutover, then the
    /// old one is retired (make before break).
    pub(super) fn cut_over(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        let LinkState::Resealing {
            live,
            route,
            next,
            params,
            ..
        } = self.state
        else {
            return;
        };
        out.push(LinkCommand::Cutover {
            from: live,
            to: next,
        });
        self.retire(live, RetireReason::Superseded, out);
        self.live.push(next);
        self.sealed_count = self.sealed_count.saturating_add(1);
        self.settings = params.settings;
        let trigger = match self.changing.take() {
            Some(setting) => PathTrigger::SettingsChange(setting),
            None => PathTrigger::Rearm,
        };
        let outcome = self.live_outcome(trigger, PunchReuse::ReusedSocket, next, route);
        out.push(self.report(outcome));
        self.state = LinkState::Up {
            incarnation: next,
            route,
            since: now,
        };
    }

    /// The reseal failed or ran out of time: the live incarnation carries on, nothing lost.
    pub(super) fn reseal_failed(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        let LinkState::Resealing {
            live, route, next, ..
        } = self.state
        else {
            return;
        };
        if self.role == Role::Leader {
            self.retire(next, RetireReason::Abandoned, out);
        }
        self.changing = None;
        self.state = LinkState::Up {
            incarnation: live,
            route,
            since: now,
        };
    }
}
