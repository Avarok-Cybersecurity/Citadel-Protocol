//! The deterministic two-party scheduler: tests only (`cfg(test)` or feature `harness`).
//!
//! Two negotiators, a network that delivers, duplicates, reorders or loses any in-flight
//! envelope on command, a model of the steered key round (the Bob-side profile check included)
//! and of local applies, and per-party clocks that jump to the next deadline. Nothing is
//! random: a schedule is a list of [`Action`]s, so every failure replays exactly.

mod check;
mod rounds;
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
    /// Rounds that reached a Loser before the frame that makes it agree.
    pub held: Vec<Round<S>>,
    pub local: Vec<(Side, Epoch)>,
    pub version: u32,
    pub dropped: bool,
    pub steps: usize,
    /// Every value either side put in a `Propose`.
    pub sent: Vec<S>,
    /// Who triggered a key round, for which epoch: only the Leader may (D2).
    pub triggered: Vec<(Side, Epoch)>,
    /// A frame was lost, a plain rekey superseded a round, or a deadline was forced while work
    /// was still in flight. Only then may
    /// a schedule end in a fallback that is not a required handshake.
    pub disturbed: bool,
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
            held: Vec::new(),
            local: Vec::new(),
            version: 0,
            dropped: false,
            steps: 0,
            sent: Vec::new(),
            triggered: Vec::new(),
            disturbed: false,
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
                let in_flight =
                    !(self.net.is_empty() && self.rounds.is_empty() && self.local.is_empty());
                self.disturbed |= in_flight && self.party(side).neg.next_wake().is_some();
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
                self.disturbed = true;
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
                self.disturbed = true; // bounded by max_apply_attempts, not by liveness
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

    pub fn step(&mut self, side: Side, input: Input<S>) {
        let party = self.party_mut(side);
        let commands = party.neg.step(party.now, input);
        let value = party.neg.current().1.clone();
        party.history.push(value);
        for command in commands {
            self.handle(side, command);
        }
        let (ready, held): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|r| r.leader.other() == side);
        self.held = held;
        for round in ready {
            self.offer_round(round);
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
            Command::ApplyKeyEpoch { epoch, value } => {
                self.triggered.push((side, epoch));
                self.rounds.push(Round {
                    leader: side,
                    epoch,
                    value,
                });
            }
            Command::ApplyLocal { epoch, .. } => self.local.push((side, epoch)),
            Command::RaiseFloor { epoch } => self.party_mut(side).floors.push(epoch),
            Command::Drop { reason, next } => {
                self.party_mut(side).drops.push((reason, next));
                self.dropped = true;
                self.rounds.clear();
                self.held.clear();
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
