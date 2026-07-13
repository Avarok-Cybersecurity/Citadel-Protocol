//! Support routines for the acquire wait loop: wake timing, janitor duty
//! (steal/evict stagnant blockers), re-enqueue after eviction, and deadline
//! cancellation.

use crate::sync::group::acquire::Grant;
use crate::sync::group::engine::Engine;
use crate::sync::group::engine_util::deadline;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::lease::{blocking_snapshot, BlockerSnapshot, ObservationWindow};
use crate::sync::group::op_types::{Op, OpOutcome};
use crate::sync::group::proposer::ProposeError;
use crate::sync::group::record::{LockRecord, PoisonInfo};
use crate::sync::group::{Fence, LockKind};
use std::time::Duration;

impl Engine {
    pub(super) async fn wait_for_wake(&self, deadline_ms: u64) {
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        let nap = self
            .cfg
            .waiter_poll_interval()
            .min(Duration::from_millis(remaining.max(1)));
        citadel_io::tokio::select! {
            _ = self.nudge.notified() => {}
            _ = citadel_io::time::sleep(nap) => {}
        }
    }

    pub(super) async fn janitor(
        &self,
        record: &LockRecord,
        nonce: u64,
        window: &mut Option<ObservationWindow>,
        steal_window_ms: u64,
        deadline_ms: u64,
    ) {
        let now = self.now_ms();
        let Some(snap) = blocking_snapshot(record, self.me(), nonce) else {
            *window = None;
            return;
        };
        let w = window.get_or_insert_with(|| ObservationWindow::start(snap, now));
        let stagnant = w.observe(snap, now);
        if !(stagnant && w.is_expired(now, steal_window_ms)) {
            return;
        }
        log::trace!(target: "citadel", "[GroupLock] {:?} janitor firing on {:?}", self.me(), w.snapshot());
        let op = match *w.snapshot() {
            BlockerSnapshot::Holder {
                member,
                nonce: target_nonce,
                fence,
                lease_seq,
            } => Op::Steal {
                target: member,
                target_nonce,
                expect_fence: fence,
                expect_lease_seq: lease_seq,
            },
            BlockerSnapshot::Waiter {
                member,
                nonce: target_nonce,
                refresh_seq,
            } => Op::EvictWaiter {
                target: member,
                target_nonce,
                expect_refresh_seq: refresh_seq,
            },
        };
        // outcome irrelevant: TargetGone/SnapshotMismatch simply mean the blocker
        // moved; the next wake re-evaluates from the committed record
        let _ = self.propose(&op, deadline_ms).await;
        *window = None;
    }

    pub(super) async fn re_enqueue(
        &self,
        nonce: u64,
        kind: LockKind,
        deadline_ms: u64,
    ) -> Result<Option<Grant>, GroupLockError> {
        let anchor_ms = self.now_ms();
        let op = Op::AcquireOrEnqueue {
            member: self.me(),
            nonce,
            kind,
            no_enqueue: false,
        };
        match self.propose(&op, deadline_ms).await {
            Ok((rec, OpOutcome::Granted { fence, recovered })) => Ok(Some(grant_from(
                &rec, nonce, fence, recovered, anchor_ms, self,
            ))),
            Ok(_) => Ok(None),
            Err(ProposeError::Denied(denied, _)) => Err(super::engine::denial_to_error(denied)),
            Err(ProposeError::QuorumUnavailable) => Err(GroupLockError::QuorumUnavailable),
        }
    }

    /// Deadline expired while queued: withdraw the request. If the cancel raced a
    /// grant, the pure Dequeue op already revoked it poison-free.
    pub(super) async fn cancel_request(&self, nonce: u64) -> Result<Grant, GroupLockError> {
        self.best_effort_dequeue(nonce).await;
        Err(GroupLockError::Timeout)
    }
}

pub(super) fn grant_from(
    record: &LockRecord,
    nonce: u64,
    fence: Fence,
    recovered: Option<PoisonInfo>,
    anchor_ms: u64,
    engine: &Engine,
) -> Grant {
    Grant {
        nonce,
        fence,
        recovered,
        value: record.value.clone(),
        value_version: record.value_version,
        valid_until_ms: deadline(anchor_ms, engine.cfg.lease_duration()),
    }
}
