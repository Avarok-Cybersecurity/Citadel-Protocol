//! Frames from the peer: put back in send order, then handled one at a time.

use super::{Negotiator, Phase, REORDER_WINDOW};
use crate::frame::{ApplyEvidence, Envelope, Frame, RejectReason, RenegotiationReason};
use crate::ids::{Epoch, Millis};
use crate::io::{Command, NegotiationState, ViolationKind};
use crate::setting::{decode_value, is_below, Setting};

impl<S: Setting> Negotiator<S> {
    pub(super) fn on_envelope(
        &mut self,
        now: Millis,
        envelope: Envelope,
        out: &mut Vec<Command<S>>,
    ) {
        if envelope.setting != S::ID {
            let state = NegotiationState::Violation {
                kind: ViolationKind::Misrouted,
            };
            return self.report(self.epoch, state, out);
        }
        if envelope.n < self.recv_n {
            return; // a duplicate of a frame already handled
        }
        if envelope.n > self.recv_n {
            if envelope.n - self.recv_n > REORDER_WINDOW {
                return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
            }
            self.ahead.insert(envelope.n, envelope.frame);
            return;
        }
        let mut next = Some(envelope.frame);
        while let Some(frame) = next {
            self.recv_n += 1;
            self.on_frame(now, frame, out);
            if self.is_closed() {
                self.ahead.clear();
                return;
            }
            next = self.ahead.remove(&self.recv_n);
        }
    }

    fn on_frame(&mut self, now: Millis, frame: Frame, out: &mut Vec<Command<S>>) {
        match frame {
            Frame::Propose {
                from_epoch,
                seq,
                value,
            } => self.on_propose(now, from_epoch, seq, value, out),
            Frame::Accept {
                from_epoch,
                seq,
                agreed,
            } => self.on_accept(now, from_epoch, seq, agreed, out),
            Frame::Reject {
                from_epoch,
                seq,
                reason,
            } => self.on_reject(from_epoch, seq, reason, out),
            Frame::Applied { epoch, evidence } => self.on_applied(epoch, evidence, out),
            Frame::Retire { epoch } => self.on_retire(epoch, out),
            // Every proposal is answered on receipt, so the answer already given wins (§4.2(5)).
            Frame::Cancel { .. } => {}
            Frame::Renegotiate { reason, next } => {
                let next = decode_value(&next).unwrap_or_else(|_| self.value.clone());
                let state = NegotiationState::FellBack {
                    reason,
                    next,
                    we_redial: self.we_redial(),
                };
                self.report(self.epoch, state, out);
                self.phase = Phase::Closed;
            }
        }
    }

    fn on_propose(
        &mut self,
        now: Millis,
        from: Epoch,
        seq: u32,
        bytes: Vec<u8>,
        out: &mut Vec<Command<S>>,
    ) {
        if from < self.epoch {
            let reason = RejectReason::Stale;
            return self.send(
                crate::frame::Frame::Reject {
                    from_epoch: from,
                    seq,
                    reason,
                },
                out,
            );
        }
        if from > self.epoch {
            return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
        }
        let theirs = match decode_value::<S>(&bytes) {
            Ok(value) if value.is_supported() => value,
            _ if matches!(self.phase, Phase::Proposing { .. }) => {
                return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
            }
            _ => {
                let reason = RejectReason::Unsupported;
                return self.send(
                    Frame::Reject {
                        from_epoch: from,
                        seq,
                        reason,
                    },
                    out,
                );
            }
        };
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => {
                let proposed = NegotiationState::Proposed {
                    value: theirs.clone(),
                    by_us: false,
                };
                self.report(self.epoch, proposed, out);
                if is_below(&self.minimum, &theirs) {
                    let state = NegotiationState::Rejected {
                        reason: RejectReason::BelowPolicy,
                        proposed: theirs,
                    };
                    self.report(self.epoch, state, out);
                    let reason = RejectReason::BelowPolicy;
                    return self.send(
                        Frame::Reject {
                            from_epoch: from,
                            seq,
                            reason,
                        },
                        out,
                    );
                }
                self.send(
                    Frame::Accept {
                        from_epoch: from,
                        seq,
                        agreed: bytes,
                    },
                    out,
                );
                self.enter_applying(now, theirs, out);
            }
            Phase::Proposing { mine, .. } => self.glare(now, mine, theirs, out),
            phase => {
                self.phase = phase;
                self.send(
                    Frame::Reject {
                        from_epoch: from,
                        seq,
                        reason: RejectReason::Busy,
                    },
                    out,
                );
            }
        }
    }

    fn on_accept(
        &mut self,
        now: Millis,
        from: Epoch,
        seq: u32,
        agreed: Vec<u8>,
        out: &mut Vec<Command<S>>,
    ) {
        let pending = matches!(&self.phase, Phase::Proposing { seq: mine, .. } if *mine == seq);
        if from != self.epoch || !pending {
            return; // an answer to a proposal that is no longer pending
        }
        let Phase::Proposing { mine, bytes, .. } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            return;
        };
        if agreed != bytes {
            return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
        }
        self.enter_applying(now, mine, out);
    }

    fn on_reject(
        &mut self,
        from: Epoch,
        seq: u32,
        reason: RejectReason,
        out: &mut Vec<Command<S>>,
    ) {
        let pending = matches!(&self.phase, Phase::Proposing { seq: mine, .. } if *mine == seq);
        if from != self.epoch || !pending {
            return;
        }
        if let Phase::Proposing { mine, .. } = std::mem::replace(&mut self.phase, Phase::Idle) {
            let state = NegotiationState::Rejected {
                reason,
                proposed: mine,
            };
            self.report(self.epoch, state, out);
        }
    }

    fn on_applied(&mut self, epoch: Epoch, evidence: ApplyEvidence, out: &mut Vec<Command<S>>) {
        if epoch <= self.epoch {
            return; // already done
        }
        match &mut self.phase {
            Phase::Applying { peer, .. } if Some(epoch) == self.epoch.next() => {
                *peer = Some(evidence)
            }
            Phase::Confirming { evidence: mine, .. } if Some(epoch) == self.epoch.next() => {
                let matches = *mine == evidence;
                self.confirm(matches, out);
            }
            _ => self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out),
        }
    }

    fn on_retire(&mut self, retired: Epoch, out: &mut Vec<Command<S>>) {
        let Some(floor) = retired.next() else {
            return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
        };
        if floor > self.epoch {
            return self.fall_back(RenegotiationReason::Desync, self.value.clone(), true, out);
        }
        if floor > self.floor {
            self.floor = floor;
            out.push(Command::RaiseFloor { epoch: floor });
        }
    }
}
