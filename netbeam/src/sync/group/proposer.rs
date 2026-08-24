//! CAS round driver: one [`Op`] as a CASPaxos round (Prepare/Promise → apply →
//! Accept/Accepted) against a majority, with ballot retry. The `ReadHint` gather
//! and the shared phase-budget/backoff helpers live in `proposer_read.rs`.

use crate::sync::group::engine::Engine;
use crate::sync::group::engine_util::PendingRound;
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::ops;
use crate::sync::group::proposer_read::merge_accepted;
use crate::sync::group::record::LockRecord;
use crate::sync::group::wire::{Ballot, GroupMsg};
use citadel_io::tokio::time::timeout;
use std::sync::atomic::Ordering;

#[derive(Debug)]
pub(crate) enum ProposeError {
    /// The op's precondition failed against the linearized record.
    Denied(OpDenied, Option<LockRecord>),
    /// No majority reachable before the deadline.
    QuorumUnavailable,
}

enum RoundAttempt {
    Committed(LockRecord, OpOutcome),
    Denied(OpDenied, Option<LockRecord>),
    Retry,
}

impl Engine {
    /// Runs `op` to commitment or denial, retrying until `deadline_ms` (local clock).
    pub(crate) async fn propose(
        &self,
        op: &Op,
        deadline_ms: u64,
    ) -> Result<(LockRecord, OpOutcome), ProposeError> {
        loop {
            match self.round(op, deadline_ms).await {
                RoundAttempt::Committed(rec, outcome) => {
                    log::trace!(target: "citadel", "[GroupLock] {:?} committed {op:?} -> {outcome:?}", self.me());
                    return Ok((rec, outcome));
                }
                RoundAttempt::Denied(denied, rec) => {
                    log::trace!(target: "citadel", "[GroupLock] {:?} denied {op:?} -> {denied:?}", self.me());
                    return Err(ProposeError::Denied(denied, rec));
                }
                RoundAttempt::Retry => {
                    if self.now_ms() >= deadline_ms {
                        return Err(ProposeError::QuorumUnavailable);
                    }
                    self.backoff().await;
                }
            }
        }
    }

    async fn round(&self, op: &Op, deadline_ms: u64) -> RoundAttempt {
        let counter = self.ballot_ctr.fetch_add(1, Ordering::Relaxed) + 1;
        if counter >= u64::MAX - (1 << 16) {
            // ballot space exhausted (only reachable under sustained attack)
            return RoundAttempt::Retry;
        }
        let ballot = Ballot {
            counter,
            proposer: self.me(),
        };
        let req_id = self.next_req_id();
        let mut pending = self.register_pending(req_id);
        self.round_inner(op, ballot, req_id, &mut pending, deadline_ms)
            .await
    }

    async fn round_inner(
        &self,
        op: &Op,
        ballot: Ballot,
        req_id: u64,
        pending: &mut PendingRound<'_>,
        deadline_ms: u64,
    ) -> RoundAttempt {
        let rx = &mut pending.rx;
        let majority = self.cfg.majority();

        // ---- phase 1: prepare ----
        let prepare = GroupMsg::Prepare { ballot };
        self.broadcast(req_id, &prepare);
        let mut promises = 0usize;
        let mut max_accepted: Option<(Ballot, LockRecord)> = None;
        if let Some(GroupMsg::Promise { accepted, .. }) = self.local_vote(&prepare) {
            promises += 1;
            merge_accepted(&mut max_accepted, accepted);
        } else {
            // local voter nacked our own ballot: a higher ballot exists; retry
            return RoundAttempt::Retry;
        }
        let phase_deadline = self.phase_deadline(deadline_ms);
        while promises < majority {
            match timeout(phase_deadline, rx.recv()).await {
                Ok(Some((
                    _,
                    GroupMsg::Promise {
                        ballot: b,
                        accepted,
                    },
                ))) if b == ballot => {
                    promises += 1;
                    merge_accepted(&mut max_accepted, accepted);
                }
                Ok(Some((
                    _,
                    GroupMsg::PrepareNack {
                        ballot: b,
                        promised,
                    },
                ))) if b == ballot => {
                    self.observe_ballot(promised);
                    return RoundAttempt::Retry;
                }
                Ok(Some(_)) => {} // stale response from an earlier round
                Ok(None) | Err(_) => return RoundAttempt::Retry,
            }
        }

        // ---- apply the pure CAS ----
        let current = max_accepted.as_ref().map(|(_, rec)| rec);
        let (record, outcome, denied) = match ops::apply(current, op) {
            Ok((rec, outcome)) => (rec, Some(outcome), None),
            Err(denied) => match current {
                // identity write: linearize the denial before reporting it
                Some(rec) => (rec.clone(), None, Some(denied)),
                None => return RoundAttempt::Denied(denied, None),
            },
        };

        // ---- phase 2: accept ----
        let accept = GroupMsg::Accept {
            ballot,
            record: record.clone(),
        };
        self.broadcast(req_id, &accept);
        // Keep gathering after a nack until a majority acked (committed) or can no
        // longer ack: bailing on the FIRST nack turns a round that in fact commits
        // (remaining acks in flight) into an ambiguous, replayed retry.
        let voters = self.cfg.members().len();
        let (mut acks, mut nacks) = (0usize, 0usize);
        match self.local_vote(&accept) {
            Some(GroupMsg::Accepted { .. }) => acks += 1,
            _ => nacks += 1, // a higher ballot exists locally; remotes may still ack
        }
        while acks < majority {
            if nacks > voters - majority {
                return RoundAttempt::Retry; // majority impossible: NOT committed
            }
            match timeout(phase_deadline, rx.recv()).await {
                Ok(Some((_, GroupMsg::Accepted { ballot: b }))) if b == ballot => acks += 1,
                Ok(Some((
                    _,
                    GroupMsg::AcceptNack {
                        ballot: b,
                        promised,
                    },
                ))) if b == ballot => {
                    self.observe_ballot(promised);
                    nacks += 1;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return RoundAttempt::Retry,
            }
        }

        match (outcome, denied) {
            (Some(outcome), _) => RoundAttempt::Committed(record, outcome),
            (None, Some(denied)) => RoundAttempt::Denied(denied, Some(record)),
            (None, None) => unreachable!("apply produced neither outcome nor denial"),
        }
    }
}
