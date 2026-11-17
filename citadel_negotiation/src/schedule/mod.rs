//! The deterministic two-party scheduler: tests only (`cfg(test)` or feature `harness`).
//!
//! Two negotiators, a network that delivers, duplicates, reorders or loses any in-flight
//! envelope on command, a model of the steered key round (the Bob-side profile check included)
//! and of local applies, and per-party clocks that jump to the next deadline. Nothing is
//! random: a schedule is a list of [`Action`]s, so every failure replays exactly.

mod check;
mod types;

pub use types::{Action, InFlight, Party, Round, Side};

use crate::frame::Frame;
use crate::ids::{Epoch, Millis};
use crate::io::{Command, Input, KeyExchangeOutcome, NegotiationState};
use crate::setting::{decode_value, Setting};
use crate::{Negotiator, NegotiatorConfig};

#[derive(Clone, Debug)]
pub struct World<S: Setting> {
    pub a: Party<S>,
    pub b: Party<S>,
    pub initial: S,
    pub net: Vec<InFlight>,
    pub rounds: Vec<Round<S>>,
    pub local: Vec<(Side, Epoch)>,
    pub version: u32,
    pub dropped: bool,
    pub steps: usize,
    /// Every value either side put in a `Propose`.
    pub sent: Vec<S>,
}

impl<S: Setting> World<S> {
    pub fn new(a: NegotiatorConfig<S>, b: NegotiatorConfig<S>, follow_minimum: bool) -> Self {
        let initial = a.initial.clone();
        let party = |config: NegotiatorConfig<S>| Party {
            history: vec![config.initial.clone()],
            neg: Negotiator::new(config).expect("a valid test configuration"),
            now: Millis(0),
            events: Vec::new(),
            drops: Vec::new(),
            floors: Vec::new(),
            follow_minimum,
        };
        World {
            a: party(a),
            b: party(b),
            initial,
            net: Vec::new(),
            rounds: Vec::new(),
            local: Vec::new(),
            version: 0,
            dropped: false,
            steps: 0,
            sent: Vec::new(),
        }
    }

    pub fn party(&self, side: Side) -> &Party<S> {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn party_mut(&mut self, side: Side) -> &mut Party<S> {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    /// Every action the network and the apply models could take next (no user actions).
    pub fn network_actions(&self, with_rekey: bool) -> Vec<Action<S>> {
        let mut actions = Vec::new();
        for (i, flight) in self.net.iter().enumerate() {
            actions.push(Action::Deliver(i));
            if !flight.duplicated {
                actions.push(Action::Duplicate(i));
            }
        }
        actions.extend((0..self.rounds.len()).map(Action::RoundArrives));
        actions.extend((0..self.local.len()).map(Action::LocalDone));
        if with_rekey && !self.rounds.is_empty() {
            actions.push(Action::PlainRekey);
        }
        actions
    }

    pub fn apply(&mut self, action: Action<S>) {
        if self.dropped && !matches!(action, Action::Deliver(_)) {
            return; // after a drop only the frames already sent are flushed
        }
        self.steps += 1;
        match action {
            Action::Request(side, value) => self.step(side, Input::Request(value)),
            Action::Cancel(side) => self.step(side, Input::Cancel),
            Action::Tick(side) => {
                let party = self.party_mut(side);
                if let Some(wake) = party.neg.next_wake() {
                    party.now = party.now.max(wake);
                }
                self.step(side, Input::Tick)
            }
            Action::Deliver(i) if i < self.net.len() => {
                let flight = self.net.remove(i);
                self.step(flight.to, Input::Recv(flight.envelope))
            }
            Action::Duplicate(i) if i < self.net.len() => {
                self.net[i].duplicated = true;
                let flight = self.net[i].clone();
                self.step(flight.to, Input::Recv(flight.envelope))
            }
            Action::Lose(i) if i < self.net.len() => {
                self.net.remove(i);
            }
            Action::RoundArrives(i) if i < self.rounds.len() => self.round_arrives(i),
            Action::LocalDone(i) if i < self.local.len() => {
                let (side, epoch) = self.local.remove(i);
                self.step(
                    side,
                    Input::LocalOutcome {
                        epoch,
                        result: Ok(()),
                    },
                )
            }
            Action::PlainRekey if !self.rounds.is_empty() => {
                let round = self.rounds.remove(0);
                self.version += 1;
                let outcome = KeyExchangeOutcome::Superseded {
                    version: self.version,
                };
                for side in [round.leader, round.leader.other()] {
                    let input = Input::KeyOutcome {
                        epoch: round.epoch,
                        outcome: outcome.clone(),
                    };
                    self.step(side, input);
                }
            }
            _ => {}
        }
    }

    /// The Leader's round reaches the Loser, who builds only the profile it agreed to (§5.1).
    fn round_arrives(&mut self, i: usize) {
        let round = self.rounds.remove(i);
        let loser = round.leader.other();
        let agreed = self.party(loser).neg.applying() == Some((round.epoch, &round.value));
        if !agreed {
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

    pub fn step(&mut self, side: Side, input: Input<S>) {
        let party = self.party_mut(side);
        let commands = party.neg.step(party.now, input);
        let value = party.neg.current().1.clone();
        party.history.push(value);
        for command in commands {
            self.handle(side, command);
        }
    }

    fn handle(&mut self, side: Side, command: Command<S>) {
        match command {
            Command::Send(envelope) if !self.dropped => {
                if let Frame::Propose { value, .. } = &envelope.frame {
                    self.sent
                        .push(decode_value(value).expect("own proposal decodes"));
                }
                self.net.push(InFlight {
                    to: side.other(),
                    envelope,
                    duplicated: false,
                });
            }
            Command::Send(_) => {}
            Command::ApplyKeyEpoch { epoch, value } => self.rounds.push(Round {
                leader: side,
                epoch,
                value,
            }),
            Command::ApplyLocal { epoch, .. } => self.local.push((side, epoch)),
            Command::RaiseFloor { epoch } => self.party_mut(side).floors.push(epoch),
            Command::Drop { reason, next } => {
                self.party_mut(side).drops.push((reason, next));
                self.dropped = true;
                self.rounds.clear();
                self.local.clear();
            }
            Command::Report(event) => {
                let applied = match &event.state {
                    NegotiationState::Applied { agreed, .. } => Some(agreed.clone()),
                    _ => None,
                };
                let party = self.party_mut(side);
                party.events.push(event);
                if let Some(agreed) = applied.filter(|_| party.follow_minimum) {
                    let _ = party.neg.step(party.now, Input::SetMinimum(agreed));
                }
            }
        }
    }
}
