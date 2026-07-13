//! Engine support: saturating time math, the RAII pending-round handle, and the
//! best-effort withdrawal helpers shared by acquire/guard error paths.

use crate::sync::group::acceptor::Acceptor;
use crate::sync::group::engine::Engine;
use crate::sync::group::op_types::Op;
use crate::sync::group::wire::GroupMsg;
use crate::sync::group::MemberId;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use std::sync::Arc;
use std::time::Duration;

/// Saturating `Duration -> millis-u64` (a `Duration::MAX` timeout must clamp,
/// not panic in debug or truncate in release).
pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Saturating deadline arithmetic on the engine-local millisecond clock.
pub(crate) fn deadline(anchor_ms: u64, d: Duration) -> u64 {
    anchor_ms.saturating_add(ms(d))
}

/// RAII handle for one in-flight request's response channel (see
/// [`Engine::register_pending`]).
pub(crate) struct PendingRound<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) req_id: u64,
    pub(crate) rx: UnboundedReceiver<(MemberId, GroupMsg)>,
}

impl Drop for PendingRound<'_> {
    fn drop(&mut self) {
        let _ = self.engine.pending.lock().remove(&self.req_id);
    }
}

/// Convenience: ops carry the local identity so often that the engine offers it.
impl Engine {
    pub(crate) fn me(&self) -> MemberId {
        self.cfg.local_id()
    }

    /// Withdraws a possibly-committed request/grant after an ambiguous failure.
    /// `Op::Dequeue` is purpose-built for this: it removes the queue entry or (for
    /// a grant whose critical section provably never ran) revokes it poison-free.
    pub(crate) async fn best_effort_dequeue(&self, nonce: u64) {
        let grace = deadline(self.now_ms(), self.cfg.round_timeout().saturating_mul(2));
        match self.propose(&self.op_dequeue(nonce), grace).await {
            Ok((rec, _)) => self.nudge_next(&rec),
            Err(err) => {
                log::trace!(target: "citadel", "[GroupLock] best-effort dequeue for nonce {nonce} unresolved: {err:?}")
            }
        }
    }

    pub(crate) fn spawn_best_effort_dequeue(self: Arc<Self>, nonce: u64) {
        if citadel_io::tokio::runtime::Handle::try_current().is_ok() {
            citadel_io::spawn(async move { self.best_effort_dequeue(nonce).await });
        }
    }

    pub(crate) fn op_dequeue(&self, nonce: u64) -> Op {
        Op::Dequeue {
            member: self.me(),
            nonce,
        }
    }
}

impl Engine {
    /// Rejects wire messages whose embedded records/ballots fail sanity bounds.
    pub(super) fn msg_sane(&self, msg: &GroupMsg) -> bool {
        match msg {
            GroupMsg::Accept { record, .. } => record.is_sane(),
            GroupMsg::Promise {
                accepted: Some((_, rec)),
                ..
            }
            | GroupMsg::ReadHintRsp {
                accepted: Some((_, rec)),
            } => rec.is_sane(),
            _ => true,
        }
    }

    pub(super) fn vote(acc: &mut Acceptor, msg: &GroupMsg) -> Option<GroupMsg> {
        use crate::sync::group::acceptor::{AcceptReply, PrepareReply};
        match msg {
            GroupMsg::Prepare { ballot } => Some(match acc.on_prepare(*ballot) {
                PrepareReply::Promise { accepted } => GroupMsg::Promise {
                    ballot: *ballot,
                    accepted,
                },
                PrepareReply::Nack { promised } => GroupMsg::PrepareNack {
                    ballot: *ballot,
                    promised,
                },
            }),
            GroupMsg::Accept { ballot, record } => {
                Some(match acc.on_accept(*ballot, record.clone()) {
                    AcceptReply::Accepted => GroupMsg::Accepted { ballot: *ballot },
                    AcceptReply::Nack { promised } => GroupMsg::AcceptNack {
                        ballot: *ballot,
                        promised,
                    },
                })
            }
            GroupMsg::ReadHint => Some(GroupMsg::ReadHintRsp {
                accepted: acc.read_hint(),
            }),
            _ => None,
        }
    }
}
