//! Local inputs: a request, a cancel, the clock.

use super::{Negotiator, Phase};
use crate::frame::{Frame, PeerSupport, RejectReason, RenegotiationReason};
use crate::ids::Millis;
use crate::io::{Command, NegotiationState};
use crate::setting::{encode_value, is_below, Setting};

impl<S: Setting> Negotiator<S> {
    pub(super) fn on_request(&mut self, now: Millis, value: S, out: &mut Vec<Command<S>>) {
        let refused = if self.phase != Phase::Idle {
            Some(RejectReason::Busy)
        } else if !value.is_supported() {
            Some(RejectReason::Unsupported)
        } else if is_below(&self.minimum, &value) {
            Some(RejectReason::BelowPolicy)
        } else {
            None
        };
        if let Some(reason) = refused {
            let state = NegotiationState::Rejected {
                reason,
                proposed: value,
            };
            return self.report(self.epoch, state, out);
        }
        if self.support == PeerSupport::Legacy {
            return self.fall_back(RenegotiationReason::PeerLegacy, value, false, out);
        }
        let bytes = match encode_value(&value) {
            Ok(bytes) => bytes,
            Err(_) => {
                let state = NegotiationState::Rejected {
                    reason: RejectReason::Unsupported,
                    proposed: value,
                };
                return self.report(self.epoch, state, out);
            }
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let frame = Frame::Propose {
            from_epoch: self.epoch,
            seq,
            value: bytes.clone(),
        };
        self.send(frame, out);
        let state = NegotiationState::Proposed {
            value: value.clone(),
            by_us: true,
        };
        self.report(self.epoch, state, out);
        let deadline = now.after(self.policy.proposal_deadline);
        self.phase = Phase::Proposing {
            seq,
            mine: value,
            bytes,
            deadline,
            cancelled: false,
        };
    }

    /// A cancel is a request to the peer, not a local decision: the proposal stays pending until
    /// the peer's answer, and an answer that agreed (or a crossed proposal) wins over the cancel.
    pub(super) fn on_cancel(&mut self, out: &mut Vec<Command<S>>) {
        let Phase::Proposing { seq, cancelled, .. } = &mut self.phase else {
            return;
        };
        if *cancelled {
            return;
        }
        *cancelled = true;
        let frame = Frame::Cancel {
            from_epoch: self.epoch,
            seq: *seq,
        };
        self.send(frame, out);
    }

    pub(super) fn on_tick(&mut self, now: Millis, out: &mut Vec<Command<S>>) {
        let Some(deadline) = self.next_wake() else {
            return;
        };
        if now < deadline {
            return;
        }
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Proposing { mine, .. } => {
                let state = NegotiationState::Rejected {
                    reason: RejectReason::TimedOut,
                    proposed: mine,
                };
                self.report(self.epoch, state, out);
                self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
            }
            Phase::Applying { agreed, .. } | Phase::Confirming { agreed, .. } => {
                self.fall_back(RenegotiationReason::ApplyFailed(S::ID), agreed, true, out);
            }
            phase @ (Phase::Idle | Phase::Closed) => self.phase = phase,
        }
    }
}
