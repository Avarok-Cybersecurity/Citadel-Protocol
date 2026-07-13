//! The acquire flow: immediate grant, FIFO wait loop (nudge + poll backstop),
//! janitor duty (steal stagnant holders / evict stagnant waiters that block us),
//! and deadline cancellation.
//!
//! Lease anchoring rule: a grant's `valid_until` is anchored at the local instant
//! the round that *could have committed it* was started — never later — so the
//! holder's own validity always expires before any observer's steal window opens.

use crate::sync::group::acquire_wait::grant_from;
use crate::sync::group::engine::Engine;
use crate::sync::group::engine_util::ms;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::lease::ObservationWindow;
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::proposer::ProposeError;
use crate::sync::group::record::PoisonInfo;
use crate::sync::group::{Fence, LockKind};
use std::time::Duration;

/// A committed grant, ready to be wrapped in a typed guard.
pub(crate) struct Grant {
    pub nonce: u64,
    pub fence: Fence,
    pub recovered: Option<PoisonInfo>,
    pub value: Vec<u8>,
    pub value_version: Fence,
    pub valid_until_ms: u64,
}

impl Engine {
    pub(crate) async fn acquire(
        &self,
        kind: LockKind,
        no_enqueue: bool,
        timeout: Duration,
    ) -> Result<Grant, GroupLockError> {
        let nonce = rand::random::<u64>();
        let anchor_ms = self.now_ms();
        let deadline_ms = anchor_ms + timeout.as_millis() as u64;
        let op = Op::AcquireOrEnqueue {
            member: self.me(),
            nonce,
            kind,
            no_enqueue,
        };
        match self.propose(&op, deadline_ms).await {
            Ok((rec, OpOutcome::Granted { fence, recovered })) => {
                Ok(grant_from(&rec, nonce, fence, recovered, anchor_ms, self))
            }
            Ok((_, OpOutcome::Enqueued { .. })) => {
                self.wait_for_grant(nonce, kind, anchor_ms, deadline_ms)
                    .await
            }
            Ok((_, other)) => Err(GroupLockError::Io(format!(
                "unexpected acquire outcome: {other:?}"
            ))),
            Err(ProposeError::Denied(denied, _)) => Err(super::engine::denial_to_error(denied)),
            Err(ProposeError::QuorumUnavailable) => Err(GroupLockError::QuorumUnavailable),
        }
    }

    /// Enqueued: wait for a nudge (or the poll backstop), refresh our entry
    /// (waiter heartbeat), claim when admissible, and janitor whatever blocks us.
    async fn wait_for_grant(
        &self,
        nonce: u64,
        kind: LockKind,
        enqueue_anchor_ms: u64,
        deadline_ms: u64,
    ) -> Result<Grant, GroupLockError> {
        let steal_window_ms = ms(self
            .cfg
            .lease_duration()
            .saturating_add(self.cfg.steal_grace()));
        let mut window: Option<ObservationWindow> = None;

        loop {
            if self.now_ms() >= deadline_ms {
                return self.cancel_request(nonce).await;
            }
            self.wait_for_wake(deadline_ms).await;

            // heartbeat our queue entry; the committed record this returns doubles
            // as our view for claiming and janitor observation
            let refresh = Op::RefreshWait {
                member: self.me(),
                nonce,
            };
            let record = match self.propose(&refresh, deadline_ms).await {
                Ok((rec, _)) => rec,
                Err(ProposeError::Denied(OpDenied::NotQueued, Some(rec))) => {
                    if let Some(h) = rec.holder(self.me(), nonce) {
                        // an earlier ambiguous round actually granted us the lock
                        let (fence, recovered) = (h.fence, h.recovered.clone());
                        return Ok(grant_from(
                            &rec,
                            nonce,
                            fence,
                            recovered,
                            enqueue_anchor_ms,
                            self,
                        ));
                    }
                    // we were evicted while slow: re-enqueue (fairness hiccup only)
                    match self.re_enqueue(nonce, kind, deadline_ms).await? {
                        Some(grant) => return Ok(grant),
                        None => continue,
                    }
                }
                Err(ProposeError::Denied(denied, _)) => {
                    return Err(super::engine::denial_to_error(denied))
                }
                Err(ProposeError::QuorumUnavailable) => {
                    return Err(GroupLockError::QuorumUnavailable)
                }
            };

            // claim when the write-preferring FIFO rule admits us
            let admissible =
                crate::sync::group::admission::is_admissible(&record, self.me(), nonce);
            log::trace!(target: "citadel", "[GroupLock] {:?} wake: admissible={admissible} holders={:?} qlen={}", self.me(), record.holders, record.queue.len());
            if admissible {
                let claim_anchor_ms = self.now_ms();
                let claim = Op::ClaimQueued {
                    member: self.me(),
                    nonce,
                };
                match self.propose(&claim, deadline_ms).await {
                    Ok((rec, OpOutcome::Granted { fence, recovered })) => {
                        return Ok(grant_from(
                            &rec,
                            nonce,
                            fence,
                            recovered,
                            claim_anchor_ms,
                            self,
                        ))
                    }
                    Ok((_, other)) => {
                        return Err(GroupLockError::Io(format!(
                            "unexpected claim outcome: {other:?}"
                        )))
                    }
                    Err(ProposeError::Denied(OpDenied::NotAdmissible, _)) => {
                        // raced another commit; observe again next wake
                        continue;
                    }
                    Err(ProposeError::Denied(OpDenied::NotQueued, Some(rec))) => {
                        if let Some(h) = rec.holder(self.me(), nonce) {
                            let (fence, recovered) = (h.fence, h.recovered.clone());
                            return Ok(grant_from(
                                &rec,
                                nonce,
                                fence,
                                recovered,
                                claim_anchor_ms,
                                self,
                            ));
                        }
                        match self.re_enqueue(nonce, kind, deadline_ms).await? {
                            Some(grant) => return Ok(grant),
                            None => continue,
                        }
                    }
                    Err(ProposeError::Denied(denied, _)) => {
                        return Err(super::engine::denial_to_error(denied))
                    }
                    Err(ProposeError::QuorumUnavailable) => {
                        return Err(GroupLockError::QuorumUnavailable)
                    }
                }
            }

            // janitor: watch whatever blocks us; steal/evict after a full frozen window
            self.janitor(&record, nonce, &mut window, steal_window_ms, deadline_ms)
                .await;
        }
    }
}
