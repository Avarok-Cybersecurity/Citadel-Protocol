//! What a shell may ask a negotiator without stepping it.

use super::{Negotiator, Phase};
use crate::ids::{Epoch, Millis, Role};
use crate::setting::Setting;

/// What the Loser's SDK does with an incoming steered key round (§5.1, the Bob-side check).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RoundAdmission {
    /// The round builds exactly the epoch and profile this side agreed: build it.
    Build,
    /// The round is for the next epoch, but the frame that makes this side agree has not
    /// arrived yet (the round can overtake it on another lane). Hold the round and ask again
    /// after the next step; the Leader's apply deadline bounds the wait.
    Wait,
    /// Not a round this side agreed to: refuse it (`KemTransferStatus::Contended`).
    Refuse,
}

impl<S: Setting> Negotiator<S> {
    /// The agreed epoch and value.
    pub fn current(&self) -> (Epoch, &S) {
        (self.epoch, &self.value)
    }

    /// The epoch and value being applied or confirmed, if any. The Bob-side check for a key round
    /// is [`admit_key_round`](Self::admit_key_round).
    pub fn applying(&self) -> Option<(Epoch, &S)> {
        match &self.phase {
            Phase::Applying { agreed, .. } | Phase::Confirming { agreed, .. } => {
                self.epoch.next().map(|next| (next, agreed))
            }
            _ => None,
        }
    }

    /// When the shell must feed `Input::Tick`; `None` when nothing is waiting on time.
    pub fn next_wake(&self) -> Option<Millis> {
        match &self.phase {
            Phase::Proposing { deadline, .. }
            | Phase::Applying { deadline, .. }
            | Phase::Confirming { deadline, .. } => Some(*deadline),
            Phase::Idle | Phase::Closed => None,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The lowest epoch the peer may still send message frames under.
    pub fn floor(&self) -> Epoch {
        self.floor
    }

    pub fn is_idle(&self) -> bool {
        self.phase == Phase::Idle
    }

    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// The Bob-side check: whether to build a key round for `epoch` carrying `value`.
    pub fn admit_key_round(&self, epoch: Epoch, value: &S) -> RoundAdmission {
        if Some(epoch) != self.epoch.next() {
            return RoundAdmission::Refuse;
        }
        match &self.phase {
            Phase::Applying {
                agreed, key: true, ..
            } if agreed == value => RoundAdmission::Build,
            Phase::Idle | Phase::Proposing { .. } => RoundAdmission::Wait,
            _ => RoundAdmission::Refuse,
        }
    }
}
