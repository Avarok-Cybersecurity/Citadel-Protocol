//! Running a world to rest, and the invariants every schedule must end in.

use super::{Action, Side, World};
use crate::io::NegotiationState;
use crate::setting::Setting;

impl<S: Setting> World<S> {
    /// Lets the network, the apply models and the clocks run in a fixed order until nothing is
    /// left to happen. `Err` when the step budget runs out: a livelock.
    pub fn run_to_quiescence(&mut self, budget: usize) -> Result<(), String> {
        let start = self.steps;
        loop {
            if self.steps - start > budget {
                return Err(format!("no quiescence within {budget} steps"));
            }
            let action = if !self.net.is_empty() {
                Action::Deliver(0)
            } else if self.dropped {
                return Ok(());
            } else if !self.rounds.is_empty() {
                Action::RoundArrives(0)
            } else if !self.local.is_empty() {
                Action::LocalDone(0)
            } else if let Some(side) = self.earliest_wake() {
                Action::Tick(side)
            } else {
                return Ok(());
            };
            self.apply(action);
        }
    }

    fn earliest_wake(&self) -> Option<Side> {
        let a = self.a.neg.next_wake().map(|at| (at, Side::A));
        let b = self.b.neg.next_wake().map(|at| (at, Side::B));
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b).1),
            (a, b) => a.or(b).map(|(_, side)| side),
        }
    }

    /// The invariants at rest (§9.1).
    ///
    /// * Either the connection was dropped deliberately, or both sides are idle at the same
    ///   epoch and value.
    /// * Each side applied each epoch at most once, in order.
    /// * With `raise_only` (an ordered setting whose minimum follows the agreed value):
    ///   no side's value ever went down (P1), the final value is the merge of the initial value
    ///   and every proposal either side sent (nothing proposed was lost), and a fallback never
    ///   names a value below where its side stood.
    pub fn check(&self, raise_only: bool) -> Result<(), String> {
        for side in [Side::A, Side::B] {
            let party = self.party(side);
            let mut last = 0u32;
            for event in &party.events {
                if let NegotiationState::Applied { .. } = event.state {
                    if event.epoch.0 != last + 1 {
                        return Err(format!(
                            "{side:?} applied epoch {:?} after {last}",
                            event.epoch
                        ));
                    }
                    last = event.epoch.0;
                }
            }
            if raise_only {
                for pair in party.history.windows(2) {
                    if S::is_downgrade(&pair[0], &pair[1]) == Some(true) {
                        return Err(format!(
                            "{side:?} went down: {:?} -> {:?}",
                            pair[0], pair[1]
                        ));
                    }
                }
                let stood = party.neg.current().1;
                for (_, next) in &party.drops {
                    if S::is_downgrade(stood, next) == Some(true) {
                        return Err(format!("{side:?} fell back to {next:?} below {stood:?}"));
                    }
                }
            }
        }
        if self.dropped {
            return Ok(());
        }
        if !self.a.neg.is_idle() || !self.b.neg.is_idle() {
            return Err("at rest, not dropped, and a side is not idle".into());
        }
        if self.a.neg.current() != self.b.neg.current() {
            let (a, b) = (self.a.neg.current(), self.b.neg.current());
            return Err(format!("sides disagree: A {a:?} B {b:?}"));
        }
        if raise_only {
            let expected = self
                .sent
                .iter()
                .fold(self.initial.clone(), |acc, v| S::merge(&acc, v));
            let got = self.a.neg.current().1;
            if *got != expected {
                return Err(format!(
                    "settled at {got:?}, but the proposals merge to {expected:?}"
                ));
            }
        }
        Ok(())
    }
}
