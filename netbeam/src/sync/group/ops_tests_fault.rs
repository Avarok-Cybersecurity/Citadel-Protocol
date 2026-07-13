//! Table tests for apply(): steal/evict/dequeue/downgrade preconditions.

use super::ops_tests::{acquire, init, m};
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::ops::apply;
use crate::sync::group::record::Holders;
use crate::sync::group::{Fence, LockKind};

#[test]
fn steal_poisons_writers_only_and_next_write_grant_recovers() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    // alive holder (advanced seq) denies the steal
    let (rec, _) = apply(
        Some(&rec),
        &Op::Renew {
            member: m(1),
            nonce: 10,
            expect_fence: Fence(1),
            expect_lease_seq: 0,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            Some(&rec),
            &Op::Steal {
                target: m(1),
                target_nonce: 10,
                expect_fence: Fence(1),
                expect_lease_seq: 0
            }
        )
        .unwrap_err(),
        OpDenied::SnapshotMismatch
    );
    // matching frozen snapshot steals + poisons
    let (rec, out) = apply(
        Some(&rec),
        &Op::Steal {
            target: m(1),
            target_nonce: 10,
            expect_fence: Fence(1),
            expect_lease_seq: 1,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Stolen);
    assert!(rec.poisoned.is_some());
    // double steal: target gone
    assert_eq!(
        apply(
            Some(&rec),
            &Op::Steal {
                target: m(1),
                target_nonce: 10,
                expect_fence: Fence(1),
                expect_lease_seq: 1
            }
        )
        .unwrap_err(),
        OpDenied::TargetGone
    );
    // next write grant consumes the poison as `recovered`
    let (rec, out) = acquire(&rec, 2, 20, LockKind::Write);
    match out {
        OpOutcome::Granted { recovered, .. } => {
            assert_eq!(recovered.unwrap().member, m(1));
        }
        other => panic!("expected grant, got {other:?}"),
    }
    assert!(rec.poisoned.is_none());
}

#[test]
fn steal_of_reader_does_not_poison() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Read);
    let (rec, out) = apply(
        Some(&rec),
        &Op::Steal {
            target: m(1),
            target_nonce: 10,
            expect_fence: Fence(1),
            expect_lease_seq: 0,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Stolen);
    assert!(rec.poisoned.is_none());
}

#[test]
fn evict_waiter_by_frozen_refresh_seq() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let (rec, _) = acquire(&rec, 2, 20, LockKind::Write);
    let (rec, _) = apply(
        Some(&rec),
        &Op::RefreshWait {
            member: m(2),
            nonce: 20,
        },
    )
    .unwrap();
    assert_eq!(
        apply(
            Some(&rec),
            &Op::EvictWaiter {
                target: m(2),
                target_nonce: 20,
                expect_refresh_seq: 0
            }
        )
        .unwrap_err(),
        OpDenied::SnapshotMismatch
    );
    let (rec, out) = apply(
        Some(&rec),
        &Op::EvictWaiter {
            target: m(2),
            target_nonce: 20,
            expect_refresh_seq: 1,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Evicted);
    assert!(rec.queue.is_empty());
}

#[test]
fn dequeue_races_grant_restores_poison_and_never_poisons_itself() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    // poison via steal, then member 2 acquires (consuming poison into its entry)
    let (rec, _) = apply(
        Some(&rec),
        &Op::Steal {
            target: m(1),
            target_nonce: 10,
            expect_fence: Fence(1),
            expect_lease_seq: 0,
        },
    )
    .unwrap();
    let (rec, out) = acquire(&rec, 2, 20, LockKind::Write);
    assert!(matches!(out, OpOutcome::Granted { ref recovered, .. } if recovered.is_some()));
    assert!(rec.poisoned.is_none());
    // member 2's cancel raced its own grant: revoke without poisoning, but the
    // original crash signal is restored for the next writer
    let (rec, out) = apply(
        Some(&rec),
        &Op::Dequeue {
            member: m(2),
            nonce: 20,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Dequeued { was_granted: true });
    assert_eq!(rec.holders, Holders::None);
    assert_eq!(rec.poisoned.as_ref().unwrap().member, m(1));
    // plain dequeue from the queue
    let (rec, _) = acquire(&rec, 3, 30, LockKind::Write);
    let (rec, _) = acquire(&rec, 4, 40, LockKind::Write);
    let (rec, out) = apply(
        Some(&rec),
        &Op::Dequeue {
            member: m(4),
            nonce: 40,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Dequeued { was_granted: false });
    assert!(rec.queue.is_empty());
}

#[test]
fn downgrade_mints_fresh_fence_and_publishes_value() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let (rec, out) = apply(
        Some(&rec),
        &Op::Downgrade {
            member: m(1),
            nonce: 10,
            expect_fence: Fence(1),
            new_value: Some(vec![9]),
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Downgraded { fence: Fence(2) });
    assert_eq!(rec.value, vec![9]);
    assert_eq!(rec.value_version, Fence(1));
    assert!(matches!(&rec.holders, Holders::Readers(hs) if hs.len() == 1));
    // same-identity downgrade against the reader entry = idempotent replay
    assert!(matches!(
        apply(
            Some(&rec),
            &Op::Downgrade {
                member: m(1),
                nonce: 10,
                expect_fence: Fence(1),
                new_value: None
            }
        ),
        Ok((_, OpOutcome::Downgraded { fence: Fence(2) }))
    ));
    // a different identity (an ordinary reader) cannot downgrade
    assert!(matches!(
        apply(
            Some(&rec),
            &Op::Downgrade {
                member: m(2),
                nonce: 20,
                expect_fence: Fence(2),
                new_value: None
            }
        ),
        Err(OpDenied::NotHolder)
    ));
}
