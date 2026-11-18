//! The steered key round: the Leader triggers it, the Loser admits, holds or refuses it.

use super::{Round, World};
use crate::io::{Input, KeyExchangeOutcome};
use crate::setting::Setting;
use crate::RoundAdmission;

impl<S: Setting> World<S> {
    /// The Leader's round reaches the Loser, who builds only the profile it agreed to (§5.1).
    pub(super) fn round_arrives(&mut self, i: usize) {
        let round = self.rounds.remove(i);
        self.offer_round(round);
    }

    /// The Loser admits, holds or refuses a round exactly as `admit_key_round` says.
    pub(super) fn offer_round(&mut self, round: Round<S>) {
        let loser = round.leader.other();
        let admission = self
            .party(loser)
            .neg
            .admit_key_round(round.epoch, &round.value);
        if admission == RoundAdmission::Wait {
            return self.held.push(round);
        }
        if admission == RoundAdmission::Refuse {
            let outcome = KeyExchangeOutcome::Refused("profile not agreed".into());
            return self.step(
                round.leader,
                Input::KeyOutcome {
                    epoch: round.epoch,
                    outcome,
                },
            );
        }
        self.version += 1;
        let outcome = KeyExchangeOutcome::Applied {
            version: self.version,
        };
        for side in [round.leader, loser] {
            self.step(
                side,
                Input::KeyOutcome {
                    epoch: round.epoch,
                    outcome: outcome.clone(),
                },
            );
        }
    }
}
