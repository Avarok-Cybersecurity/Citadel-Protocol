//! Agreement and the apply step: glare, the key round or local apply, confirmation.

use super::{Negotiator, Phase};
use crate::frame::{ApplyEvidence, Frame, RejectReason, RenegotiationReason};
use crate::ids::{Epoch, Millis, Role};
use crate::io::{Command, KeyExchangeOutcome, NegotiationState};
use crate::setting::{encode_value, value_digest, ApplyPath, Setting};

impl<S: Setting> Negotiator<S> {
    /// Both sides proposed in the same epoch. Each crossed `Propose` is the other's acceptance:
    /// both compute `merge(leader's, loser's)` from the same inputs and move on, with no extra
    /// round trip. A merge that would lower the setting is refused on both sides alike.
    pub(super) fn glare(&mut self, now: Millis, mine: S, theirs: S, out: &mut Vec<Command<S>>) {
        let agreed = match self.role {
            Role::Leader => S::merge(&mine, &theirs),
            Role::Loser => S::merge(&theirs, &mine),
        };
        if S::is_downgrade(&self.value, &agreed) == Some(true) {
            self.phase = Phase::Idle;
            let state = NegotiationState::Rejected {
                reason: RejectReason::Crossed,
                proposed: mine,
            };
            return self.report(self.epoch, state, out);
        }
        if agreed != mine {
            let state = NegotiationState::Rejected {
                reason: RejectReason::Superseded,
                proposed: mine,
            };
            self.report(self.epoch, state, out);
        }
        self.enter_applying(now, agreed, out);
    }

    pub(super) fn enter_applying(&mut self, now: Millis, agreed: S, out: &mut Vec<Command<S>>) {
        let Some(next) = self.epoch.next() else {
            return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
        };
        self.report(
            next,
            NegotiationState::Accepted {
                agreed: agreed.clone(),
            },
            out,
        );
        let key = match self.path_to(&agreed) {
            ApplyPath::Handshake => {
                let reason = RenegotiationReason::HandshakeRequired(S::ID);
                return self.fall_back(reason, agreed, true, out);
            }
            ApplyPath::InBandKeyEpoch => true,
            ApplyPath::InBandLocal => false,
        };
        let deadline = now.after(self.policy.apply_deadline);
        if !key {
            out.push(Command::ApplyLocal {
                epoch: next,
                value: agreed.clone(),
            });
        } else if self.role == Role::Leader {
            out.push(Command::ApplyKeyEpoch {
                epoch: next,
                value: agreed.clone(),
            });
        }
        self.phase = Phase::Applying {
            agreed,
            key,
            deadline,
            attempts: 1,
            peer: None,
        };
    }

    pub(super) fn on_key_outcome(
        &mut self,
        now: Millis,
        epoch: Epoch,
        outcome: KeyExchangeOutcome,
        out: &mut Vec<Command<S>>,
    ) {
        let Phase::Applying {
            agreed,
            key: true,
            deadline,
            attempts,
            ..
        } = &mut self.phase
        else {
            return;
        };
        if Some(epoch) != self.epoch.next() {
            return; // the outcome of a round this negotiator is no longer waiting for
        }
        match outcome {
            KeyExchangeOutcome::Applied { version } => self.applied(now, Some(version), out),
            KeyExchangeOutcome::Superseded { .. } => {
                *attempts = attempts.saturating_add(1);
                if *attempts > self.policy.max_apply_attempts {
                    let agreed = agreed.clone();
                    return self.fall_back(
                        RenegotiationReason::ApplyFailed(S::ID),
                        agreed,
                        true,
                        out,
                    );
                }
                *deadline = now.after(self.policy.apply_deadline);
                if self.role == Role::Leader {
                    out.push(Command::ApplyKeyEpoch {
                        epoch,
                        value: agreed.clone(),
                    });
                }
            }
            KeyExchangeOutcome::Refused(_) | KeyExchangeOutcome::Failed(_) => {
                let agreed = agreed.clone();
                self.fall_back(RenegotiationReason::ApplyFailed(S::ID), agreed, true, out);
            }
        }
    }

    pub(super) fn on_local_outcome(
        &mut self,
        now: Millis,
        epoch: Epoch,
        result: Result<(), String>,
        out: &mut Vec<Command<S>>,
    ) {
        let Phase::Applying {
            agreed, key: false, ..
        } = &self.phase
        else {
            return;
        };
        if Some(epoch) != self.epoch.next() {
            return;
        }
        match result {
            Ok(()) => self.applied(now, None, out),
            Err(_) => {
                let agreed = agreed.clone();
                self.fall_back(RenegotiationReason::ApplyFailed(S::ID), agreed, true, out);
            }
        }
    }

    fn applied(&mut self, now: Millis, version: Option<u32>, out: &mut Vec<Command<S>>) {
        let Phase::Applying { agreed, peer, .. } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            return;
        };
        let (Some(next), Ok(bytes)) = (self.epoch.next(), encode_value(&agreed)) else {
            return self.fall_back(RenegotiationReason::Desync, agreed, true, out);
        };
        let evidence = ApplyEvidence {
            version,
            digest: value_digest(&bytes),
        };
        self.send(
            Frame::Applied {
                epoch: next,
                evidence,
            },
            out,
        );
        let deadline = now.after(self.policy.apply_deadline);
        self.phase = Phase::Confirming {
            agreed,
            evidence,
            deadline,
        };
        if let Some(theirs) = peer {
            self.confirm(theirs == evidence, out);
        }
    }

    /// Both sides applied: the epoch is done when their evidence agrees, a desync when not.
    pub(super) fn confirm(&mut self, matches: bool, out: &mut Vec<Command<S>>) {
        let Phase::Confirming {
            agreed, evidence, ..
        } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            return;
        };
        let Some(next) = self.epoch.next().filter(|_| matches) else {
            return self.fall_back(RenegotiationReason::Desync, agreed, true, out);
        };
        let retired = self.epoch;
        self.epoch = next;
        self.value = agreed.clone();
        self.next_seq = 0;
        self.send(Frame::Retire { epoch: retired }, out);
        let state = NegotiationState::Applied {
            agreed,
            version: evidence.version,
        };
        self.report(next, state, out);
    }
}
