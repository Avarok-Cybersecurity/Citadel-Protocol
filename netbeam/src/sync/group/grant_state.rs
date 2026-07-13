//! Shared per-grant state: lease bookkeeping, the renew (heartbeat) task, and the
//! release/downgrade CAS flows used by every guard type.

use crate::sync::group::acquire::Grant;
use crate::sync::group::engine::Engine;
use crate::sync::group::engine_util::deadline;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::proposer::ProposeError;
use crate::sync::group::Fence;
use citadel_io::tokio::sync::watch;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub(crate) struct GrantState {
    pub(crate) engine: Arc<Engine>,
    pub(crate) nonce: u64,
    pub(crate) fence: Fence,
    lease_seq: AtomicU64,
    valid_until_ms: AtomicU64,
    invalid_tx: watch::Sender<bool>,
    released: AtomicBool,
}

impl GrantState {
    pub(crate) fn new(engine: Arc<Engine>, grant: &Grant) -> Arc<Self> {
        let (invalid_tx, _) = watch::channel(false);
        let state = Arc::new(Self {
            engine,
            nonce: grant.nonce,
            fence: grant.fence,
            lease_seq: AtomicU64::new(0),
            valid_until_ms: AtomicU64::new(grant.valid_until_ms),
            invalid_tx,
            released: AtomicBool::new(false),
        });
        let renewer = state.clone();
        citadel_io::spawn(async move { renewer.renew_loop().await });
        state
    }

    pub(crate) fn is_valid(&self) -> bool {
        !*self.invalid_tx.borrow()
            && self.engine.now_ms() < self.valid_until_ms.load(Ordering::Acquire)
    }

    pub(crate) async fn invalidated(&self) {
        let mut rx = self.invalid_tx.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    fn mark_invalid(&self) {
        log::trace!(target: "citadel", "[GroupLock] {:?} grant fence={:?} marked invalid", self.engine.me(), self.fence);
        // send_replace, not send: `send` is a no-op when no receiver is subscribed
        // yet, which would leave is_valid()/invalidated() permanently stale
        let _ = self.invalid_tx.send_replace(true);
    }

    /// Holder heartbeat. Validity is re-anchored at each renew round's START, so the
    /// holder's view expires strictly before any observer's steal window (which opens
    /// only after `lease_duration + steal_grace` of observed stagnation).
    async fn renew_loop(self: Arc<Self>) {
        let interval = self.engine.cfg.renew_interval();
        loop {
            citadel_io::time::sleep(interval).await;
            if self.released.load(Ordering::Acquire) {
                return;
            }
            let anchor_ms = self.engine.now_ms();
            let deadline_ms = self.valid_until_ms.load(Ordering::Acquire);
            let op = Op::Renew {
                member: self.engine.me(),
                nonce: self.nonce,
                expect_fence: self.fence,
                expect_lease_seq: self.lease_seq.load(Ordering::Acquire),
            };
            match self.engine.propose(&op, deadline_ms).await {
                Ok((_, OpOutcome::Renewed { lease_seq })) => {
                    self.lease_seq.store(lease_seq, Ordering::Release);
                    let new_deadline = deadline(anchor_ms, self.engine.cfg.lease_duration());
                    self.valid_until_ms.store(new_deadline, Ordering::Release);
                }
                Ok((_, other)) => {
                    log::warn!(target: "citadel", "[GroupLock] unexpected renew outcome: {other:?}");
                }
                Err(ProposeError::Denied(_, _)) => {
                    // fence/seq moved on: we were stolen
                    self.mark_invalid();
                    return;
                }
                Err(ProposeError::QuorumUnavailable) => {
                    if self.engine.now_ms() >= self.valid_until_ms.load(Ordering::Acquire) {
                        // could not renew within our own validity: self-invalidate
                        self.mark_invalid();
                        return;
                    }
                }
            }
        }
    }

    /// Removes the grant. `new_value` = serialized T when the guard mutated it.
    ///
    /// Always attempts the Release CAS, even after local self-invalidation: the CAS
    /// is fence-guarded, so if the entry was never actually stolen (e.g. a partition
    /// healed before anyone's steal window elapsed) this both cleans up promptly and
    /// legitimately publishes the value — mutual exclusion held the entire time.
    /// A genuinely stolen grant is denied and surfaced as `Stolen`.
    pub(crate) async fn release(&self, new_value: Option<Vec<u8>>) -> Result<(), GroupLockError> {
        if self.released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let deadline_ms = deadline(self.engine.now_ms(), self.engine.cfg.acquire_timeout());
        let op = Op::Release {
            member: self.engine.me(),
            nonce: self.nonce,
            expect_fence: self.fence,
            new_value,
        };
        match self.engine.propose(&op, deadline_ms).await {
            Ok((rec, _)) => {
                self.engine.nudge_next(&rec);
                Ok(())
            }
            Err(ProposeError::Denied(OpDenied::NotHolder, rec)) => {
                self.mark_invalid();
                if let Some(rec) = &rec {
                    self.engine.nudge_next(rec);
                }
                Err(GroupLockError::Stolen { fence: self.fence })
            }
            Err(ProposeError::Denied(denied, _)) => Err(super::engine::denial_to_error(denied)),
            Err(ProposeError::QuorumUnavailable) => {
                // ambiguous: keep retrying in the background until the CAS commits,
                // is denied (stolen), or the steal window has certainly elapsed —
                // without this, a transient quorum loss abandons a live grant
                self.spawn_release_retry(op);
                Err(GroupLockError::QuorumUnavailable)
            }
        }
    }

    /// Detached bounded retry for an ambiguous release. Fence-guarded, so replays
    /// are idempotent (`last_released` tombstone) and steals deny it.
    fn spawn_release_retry(&self, op: Op) {
        let engine = self.engine.clone();
        let retry_window = self
            .engine
            .cfg
            .lease_duration()
            .saturating_add(self.engine.cfg.steal_grace())
            .saturating_mul(2);
        if citadel_io::tokio::runtime::Handle::try_current().is_ok() {
            citadel_io::spawn(async move {
                let deadline_ms = deadline(engine.now_ms(), retry_window);
                match engine.propose(&op, deadline_ms).await {
                    Ok((rec, _)) => engine.nudge_next(&rec),
                    Err(err) => {
                        log::trace!(target: "citadel", "[GroupLock] background release retry ended: {err:?}")
                    }
                }
            });
        }
    }

    /// Atomically converts this write grant into a read grant with a fresh fence.
    pub(crate) async fn downgrade(
        &self,
        new_value: Option<Vec<u8>>,
    ) -> Result<Grant, GroupLockError> {
        if self.released.swap(true, Ordering::AcqRel) {
            return Err(GroupLockError::Io("grant already released".to_string()));
        }
        if *self.invalid_tx.borrow() {
            return Err(GroupLockError::Stolen { fence: self.fence });
        }
        let anchor_ms = self.engine.now_ms();
        let deadline_ms = deadline(anchor_ms, self.engine.cfg.acquire_timeout());
        let op = Op::Downgrade {
            member: self.engine.me(),
            nonce: self.nonce,
            expect_fence: self.fence,
            new_value,
        };
        match self.engine.propose(&op, deadline_ms).await {
            Ok((rec, OpOutcome::Downgraded { fence })) => {
                // newly-admissible readers may now claim alongside us
                self.engine.nudge_next(&rec);
                Ok(Grant {
                    nonce: self.nonce,
                    fence,
                    recovered: None,
                    value: rec.value.clone(),
                    value_version: rec.value_version,
                    valid_until_ms: deadline(anchor_ms, self.engine.cfg.lease_duration()),
                })
            }
            Ok((_, other)) => Err(GroupLockError::Io(format!(
                "unexpected downgrade outcome: {other:?}"
            ))),
            Err(ProposeError::Denied(OpDenied::NotHolder, _)) => {
                self.mark_invalid();
                Err(GroupLockError::Stolen { fence: self.fence })
            }
            Err(ProposeError::Denied(denied, _)) => Err(super::engine::denial_to_error(denied)),
            Err(ProposeError::QuorumUnavailable) => {
                // the downgrade may or may not have committed; Dequeue removes
                // whichever entry (writer or downgraded reader) exists, poison-free
                self.engine.clone().spawn_best_effort_dequeue(self.nonce);
                Err(GroupLockError::QuorumUnavailable)
            }
        }
    }

    /// Best-effort release used from guard `Drop` (existing netbeam idiom).
    pub(crate) fn spawn_release(self: Arc<Self>, new_value: Option<Vec<u8>>) {
        if self.released.load(Ordering::Acquire) {
            return; // explicit release/downgrade already consumed the grant
        }
        if citadel_io::tokio::runtime::Handle::try_current().is_ok() {
            citadel_io::spawn(async move {
                if let Err(err) = self.release(new_value).await {
                    log::warn!(target: "citadel", "[GroupLock] drop-release failed: {err}");
                }
            });
        } else {
            // no runtime: the wire release cannot run, but the renew task (if its
            // runtime still lives) must stop heartbeating or the lease renews
            // forever and peers can never steal the abandoned grant
            self.released.store(true, Ordering::Release);
            self.mark_invalid();
            log::warn!(target: "citadel", "[GroupLock] no runtime for drop-release; peers will steal after the lease window");
        }
    }
}
