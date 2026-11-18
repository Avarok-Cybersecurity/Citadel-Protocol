//! The scheduler's vocabulary: the two sides, what each holds, and what can happen next.

use crate::frame::{Envelope, RenegotiationReason};
use crate::ids::{Epoch, Millis};
use crate::io::NegotiationEvent;
use crate::setting::Setting;
use crate::Negotiator;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Party<S: Setting> {
    pub neg: Negotiator<S>,
    pub now: Millis,
    pub events: Vec<NegotiationEvent<S>>,
    /// The agreed value after every step, oldest first.
    pub history: Vec<S>,
    pub drops: Vec<(RenegotiationReason, S)>,
    pub floors: Vec<Epoch>,
    /// Writes every applied value back as the minimum, as the agent's preference store does.
    pub follow_minimum: bool,
}

#[derive(Clone, Debug)]
pub struct InFlight {
    pub to: Side,
    pub envelope: Envelope,
    pub duplicated: bool,
}

#[derive(Clone, Debug)]
pub struct Round<S> {
    pub leader: Side,
    pub epoch: Epoch,
    pub value: S,
}

#[derive(Clone, Debug)]
pub enum Action<S> {
    Request(Side, S),
    Cancel(Side),
    Tick(Side),
    Deliver(usize),
    Duplicate(usize),
    Lose(usize),
    RoundArrives(usize),
    LocalDone(usize),
    PlainRekey,
}
