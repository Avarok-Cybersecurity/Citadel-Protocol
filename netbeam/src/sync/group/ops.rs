//! Every lock-semantic transition, expressed as one pure compare-and-swap function:
//! [`apply`]. All safety preconditions live here; the consensus layer merely
//! linearizes calls to this function. Every op is idempotent under re-application
//! after an ambiguous (timed-out) round — grants record their consumed poison in
//! the holder entry so a retried acquire/claim reports the same `recovered` info.

use crate::sync::group::admission;
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::ops_grant::grant;
use crate::sync::group::record::{HolderEntry, Holders, LockRecord, PoisonInfo, WaitEntry};
use crate::sync::group::LockKind;

/// The pure CAS transition. Returns `(successor_record, outcome)`; a denial leaves
/// the record untouched (the proposer commits an identity write to linearize it).
pub fn apply(current: Option<&LockRecord>, op: &Op) -> Result<(LockRecord, OpOutcome), OpDenied> {
    let mut rec = match (current, op) {
        (None, Op::Init { value }) => {
            return Ok((LockRecord::initial(value.clone()), OpOutcome::Initialized))
        }
        (Some(_), Op::Init { .. }) => return Err(OpDenied::AlreadyInitialized),
        (None, _) => return Err(OpDenied::Uninitialized),
        (Some(rec), _) => rec.clone(),
    };

    match op {
        Op::Init { .. } => unreachable!("handled above"),

        Op::AcquireOrEnqueue {
            member,
            nonce,
            kind,
            no_enqueue,
        } => {
            if let Some(h) = rec.holder(*member, *nonce) {
                // idempotent retry of a committed grant
                let outcome = OpOutcome::Granted {
                    fence: h.fence,
                    recovered: h.recovered.clone(),
                };
                return Ok((rec, outcome));
            }
            if let Some((pos, _)) = rec.wait_entry(*member, *nonce) {
                return Ok((rec, OpOutcome::Enqueued { position: pos }));
            }
            if admission::immediate_grant_allowed(&rec, *kind) {
                let outcome = grant(&mut rec, *member, *nonce, *kind)?;
                Ok((rec, outcome))
            } else if *no_enqueue {
                Err(OpDenied::WouldBlock)
            } else {
                rec.queue.push(WaitEntry {
                    member: *member,
                    nonce: *nonce,
                    kind: *kind,
                    refresh_seq: 0,
                });
                let position = rec.queue.len() - 1;
                Ok((rec, OpOutcome::Enqueued { position }))
            }
        }

        Op::ClaimQueued { member, nonce } => {
            if let Some(h) = rec.holder(*member, *nonce) {
                let outcome = OpOutcome::Granted {
                    fence: h.fence,
                    recovered: h.recovered.clone(),
                };
                return Ok((rec, outcome));
            }
            if rec.wait_entry(*member, *nonce).is_none() {
                return Err(OpDenied::NotQueued);
            }
            if !admission::is_admissible(&rec, *member, *nonce) {
                return Err(OpDenied::NotAdmissible);
            }
            let entry = rec.remove_wait_entry(*member, *nonce).expect("checked");
            let outcome = grant(&mut rec, *member, *nonce, entry.kind)?;
            Ok((rec, outcome))
        }

        Op::RefreshWait { member, nonce } => {
            if rec.holder(*member, *nonce).is_some() {
                // raced a grant; the waiter will discover this on its next claim
                return Err(OpDenied::NotQueued);
            }
            let Some(idx) = rec
                .queue
                .iter()
                .position(|w| w.member == *member && w.nonce == *nonce)
            else {
                return Err(OpDenied::NotQueued);
            };
            rec.queue[idx].refresh_seq = rec.queue[idx]
                .refresh_seq
                .checked_add(1)
                .ok_or(OpDenied::CounterExhausted)?;
            Ok((rec, OpOutcome::Refreshed))
        }

        Op::Renew {
            member,
            nonce,
            expect_fence,
            expect_lease_seq,
        } => {
            let Some(h) = rec.holder_mut(*member, *nonce) else {
                return Err(OpDenied::NotHolder);
            };
            if h.fence != *expect_fence {
                return Err(OpDenied::NotHolder);
            }
            if h.lease_seq == *expect_lease_seq {
                h.lease_seq = h
                    .lease_seq
                    .checked_add(1)
                    .ok_or(OpDenied::CounterExhausted)?;
            } else if h.lease_seq != *expect_lease_seq + 1 {
                // neither fresh nor an idempotent replay of the previous renew
                return Err(OpDenied::NotHolder);
            }
            let lease_seq = h.lease_seq;
            Ok((rec, OpOutcome::Renewed { lease_seq }))
        }

        Op::Release {
            member,
            nonce,
            expect_fence,
            new_value,
        } => {
            if rec.holder(*member, *nonce).is_none() {
                // idempotent replay of a committed release (tombstone or value fence)
                if rec.last_released == Some((*member, *nonce, *expect_fence))
                    || (new_value.is_some() && rec.value_version == *expect_fence)
                {
                    return Ok((rec, OpOutcome::Released));
                }
                return Err(OpDenied::NotHolder);
            }
            let (h, _) = rec.remove_holder(*member, *nonce).expect("checked above");
            if h.fence != *expect_fence {
                return Err(OpDenied::NotHolder);
            }
            if let Some(v) = new_value {
                rec.value = v.clone();
                rec.value_version = *expect_fence;
            }
            rec.last_released = Some((*member, *nonce, *expect_fence));
            Ok((rec, OpOutcome::Released))
        }

        Op::Downgrade {
            member,
            nonce,
            expect_fence,
            new_value,
        } => {
            // idempotent replay: a committed downgrade left this (member, nonce) as
            // a reader entry (nonces are per-acquire, so aliasing is impossible)
            if let (Holders::Readers(_), Some(h)) = (&rec.holders, rec.holder(*member, *nonce)) {
                let fence = h.fence;
                return Ok((rec, OpOutcome::Downgraded { fence }));
            }
            match &rec.holders {
                Holders::Writer(h)
                    if h.member == *member && h.nonce == *nonce && h.fence == *expect_fence => {}
                _ => return Err(OpDenied::NotHolder),
            }
            if let Some(v) = new_value {
                rec.value = v.clone();
                rec.value_version = *expect_fence;
            }
            let fence = rec.next_fence().ok_or(OpDenied::CounterExhausted)?;
            rec.holders = Holders::Readers(vec![HolderEntry {
                member: *member,
                nonce: *nonce,
                fence,
                lease_seq: 0,
                recovered: None,
            }]);
            Ok((rec, OpOutcome::Downgraded { fence }))
        }

        Op::Steal {
            target,
            target_nonce,
            expect_fence,
            expect_lease_seq,
        } => {
            let Some(h) = rec.holder(*target, *target_nonce) else {
                return Err(OpDenied::TargetGone);
            };
            if h.fence != *expect_fence || h.lease_seq != *expect_lease_seq {
                return Err(OpDenied::SnapshotMismatch);
            }
            let (h, kind) = rec
                .remove_holder(*target, *target_nonce)
                .expect("checked above");
            if kind == LockKind::Write {
                rec.poisoned = Some(PoisonInfo {
                    member: h.member,
                    fence: h.fence,
                });
            }
            Ok((rec, OpOutcome::Stolen))
        }

        Op::EvictWaiter {
            target,
            target_nonce,
            expect_refresh_seq,
        } => {
            let Some((_, w)) = rec.wait_entry(*target, *target_nonce) else {
                return Err(OpDenied::TargetGone);
            };
            if w.refresh_seq != *expect_refresh_seq {
                return Err(OpDenied::SnapshotMismatch);
            }
            rec.remove_wait_entry(*target, *target_nonce);
            Ok((rec, OpOutcome::Evicted))
        }

        Op::Dequeue { member, nonce } => {
            if rec.remove_wait_entry(*member, *nonce).is_some() {
                return Ok((rec, OpOutcome::Dequeued { was_granted: false }));
            }
            if let Some((h, _)) = rec.remove_holder(*member, *nonce) {
                // cancel raced the grant: revoke without poison, restoring any
                // poison this grant had consumed (the CS provably never ran)
                if rec.poisoned.is_none() {
                    rec.poisoned = h.recovered;
                }
                return Ok((rec, OpOutcome::Dequeued { was_granted: true }));
            }
            Err(OpDenied::NotQueued)
        }
    }
}
