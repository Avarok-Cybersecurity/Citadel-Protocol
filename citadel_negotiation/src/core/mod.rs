//! The pure negotiator: one per `(connection, setting)`.
//!
//! `step(now, input) -> Vec<Command>` is the whole interface. Nothing here reads a clock, sends
//! a byte or draws a random number; the transitions are the oracle the schedule tests check.

mod apply;
mod inbound;
mod local;
mod query;

pub use query::RoundAdmission;

use crate::frame::{ApplyEvidence, Envelope, Frame, PeerSupport, RenegotiationReason};
use crate::ids::{Cid, Epoch, Millis, Role};
use crate::io::{Command, Input, NegotiationEvent, NegotiationState};
use crate::policy::{NegotiationPolicy, PolicyError};
use crate::setting::{encode_value, is_below, ApplyPath, Setting};
use std::collections::BTreeMap;

/// The most envelopes a receiver buffers ahead of a gap. An honest peer sends a handful per
/// epoch; a gap wider than this is a broken lane.
pub const REORDER_WINDOW: u64 = 64;

/// Everything a negotiator needs; nothing has a default.
#[derive(Clone, Debug)]
pub struct NegotiatorConfig<S> {
    pub local: Cid,
    pub peer: Cid,
    /// The value the channel opened with (the SDK getter's negotiated settings), epoch 0.
    pub initial: S,
    /// The local minimum for this peer: proposals below it are refused, from either side.
    pub minimum: S,
    /// What the peer's `Hello` said about this setting.
    pub support: PeerSupport,
    pub policy: NegotiationPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    SameCid,
    Policy(PolicyError),
    UnsupportedInitial,
    InitialBelowMinimum,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phase<S> {
    Idle,
    Proposing {
        seq: u32,
        mine: S,
        bytes: Vec<u8>,
        deadline: Millis,
        cancelled: bool,
    },
    Applying {
        agreed: S,
        key: bool,
        deadline: Millis,
        attempts: u8,
        peer: Option<ApplyEvidence>,
    },
    Confirming {
        agreed: S,
        evidence: ApplyEvidence,
        deadline: Millis,
    },
    Closed,
}

#[derive(Clone, Debug)]
pub struct Negotiator<S: Setting> {
    role: Role,
    support: PeerSupport,
    policy: NegotiationPolicy,
    minimum: S,
    epoch: Epoch,
    value: S,
    next_seq: u32,
    floor: Epoch,
    send_n: u64,
    recv_n: u64,
    ahead: BTreeMap<u64, Frame>,
    phase: Phase<S>,
}

impl<S: Setting> Negotiator<S> {
    pub fn new(config: NegotiatorConfig<S>) -> Result<Self, ConfigError> {
        let role = Role::for_pair(config.local, config.peer).ok_or(ConfigError::SameCid)?;
        config.policy.validate().map_err(ConfigError::Policy)?;
        if !config.initial.is_supported() {
            return Err(ConfigError::UnsupportedInitial);
        }
        if is_below(&config.minimum, &config.initial) {
            return Err(ConfigError::InitialBelowMinimum);
        }
        Ok(Self {
            role,
            support: config.support,
            policy: config.policy,
            minimum: config.minimum,
            epoch: Epoch(0),
            value: config.initial,
            next_seq: 0,
            floor: Epoch(0),
            send_n: 0,
            recv_n: 0,
            ahead: BTreeMap::new(),
            phase: Phase::Idle,
        })
    }

    pub fn step(&mut self, now: Millis, input: Input<S>) -> Vec<Command<S>> {
        let mut out = Vec::new();
        if self.is_closed() {
            return out;
        }
        match input {
            Input::Request(value) => self.on_request(now, value, &mut out),
            Input::Cancel => self.on_cancel(&mut out),
            Input::Recv(envelope) => self.on_envelope(now, envelope, &mut out),
            Input::KeyOutcome { epoch, outcome } => {
                self.on_key_outcome(now, epoch, outcome, &mut out)
            }
            Input::LocalOutcome { epoch, result } => {
                self.on_local_outcome(now, epoch, result, &mut out)
            }
            Input::SetMinimum(minimum) => self.minimum = minimum,
            Input::SendFailed => self.fall_back(
                RenegotiationReason::Desync,
                self.value.clone(),
                false,
                &mut out,
            ),
            Input::Tick => self.on_tick(now, &mut out),
        }
        out
    }

    fn send(&mut self, frame: Frame, out: &mut Vec<Command<S>>) {
        let n = self.send_n;
        self.send_n += 1;
        out.push(Command::Send(Envelope {
            setting: S::ID,
            n,
            frame,
        }));
    }

    fn report(&self, epoch: Epoch, state: NegotiationState<S>, out: &mut Vec<Command<S>>) {
        out.push(Command::Report(NegotiationEvent {
            setting: S::ID,
            epoch,
            state,
        }));
    }

    fn we_redial(&self) -> bool {
        self.support == PeerSupport::Legacy || self.role == Role::Leader
    }

    /// The deliberate drop. The side that originates it tells the peer why (when there is a lane)
    /// and disconnects; a side closing because the peer said `Renegotiate` does neither.
    fn fall_back(
        &mut self,
        reason: RenegotiationReason,
        next: S,
        lane: bool,
        out: &mut Vec<Command<S>>,
    ) {
        let we_redial = self.we_redial();
        let state = NegotiationState::FellBack {
            reason,
            next: next.clone(),
            we_redial,
        };
        self.report(self.epoch, state, out);
        if lane && self.support == PeerSupport::InBand {
            match encode_value(&next) {
                Ok(bytes) => self.send(
                    Frame::Renegotiate {
                        reason,
                        next: bytes,
                    },
                    out,
                ),
                Err(_) => self.send(
                    Frame::Renegotiate {
                        reason: RenegotiationReason::Desync,
                        next: Vec::new(),
                    },
                    out,
                ),
            }
        }
        out.push(Command::Drop { reason, next });
        self.phase = Phase::Closed;
    }

    fn path_to(&self, agreed: &S) -> ApplyPath {
        S::path(&self.value, agreed)
    }
}
