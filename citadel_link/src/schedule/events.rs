//! The world's own events: an agreement both ends hold, and a path lost at both ends.

use super::{Side, World};
use crate::core::LinkInput;
use crate::kind::{Epoch, SettingId};
use crate::LinkState;

impl World {
    /// The negotiator agrees only over a live lane: both ends up.
    pub(super) fn agree(&mut self, agreed: crate::decision::LinkSettings) {
        let up = |w: &World, side| matches!(w.state(side), LinkState::Up { .. });
        if !(up(self, Side::A) && up(self, Side::B)) {
            return;
        }
        let from = self.a.core.settings();
        let caps = self.a.core.config().caps;
        let decision = crate::decision::decide(&from, &agreed, caps);
        self.server_needed |= matches!(decision, crate::SettingsDecision::Reestablish { .. });
        self.epoch += 1;
        // Both ends hold the agreement before either acts on it (the negotiator's evidence is
        // exchanged before `Applied`), so a re-establishment is not a loss seen from the other.
        self.agreeing = true;
        for side in [Side::A, Side::B] {
            let input = LinkInput::SettingsAgreed {
                epoch: Epoch(self.epoch),
                setting: SettingId::KEY_PROFILE,
                agreed,
            };
            self.step(side, input);
        }
        self.agreeing = false;
    }

    pub(super) fn lose(&mut self, cause: crate::event::LossCause) {
        for side in [Side::A, Side::B] {
            let live = match self.state(side) {
                LinkState::Up { incarnation, .. } => Some(*incarnation),
                LinkState::Resealing { live, .. } => Some(*live),
                _ => None,
            };
            if let Some(incarnation) = live {
                self.step(side, LinkInput::LinkLost { incarnation, cause });
            }
        }
    }

    /// A path that dies, dies at both ends: when a side degrades on its own (a network change, a
    /// failed rebind or probe), the other side's copy of the path is lost too.
    pub(super) fn lose_one(&mut self, side: Side) {
        let live = match self.state(side) {
            LinkState::Up { incarnation, .. } => Some(*incarnation),
            LinkState::Resealing { live, .. } => Some(*live),
            _ => None,
        };
        if let Some(incarnation) = live {
            let cause = crate::event::LossCause::Transient;
            self.step(side, LinkInput::LinkLost { incarnation, cause });
        }
    }
}
