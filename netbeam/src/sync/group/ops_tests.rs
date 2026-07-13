//! Table tests for every `apply()` precondition (loaded from ops.rs as
//! `#[cfg(test)] #[path = "ops_tests.rs"]`).

use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::ops::apply;
use crate::sync::group::record::{Holders, LockRecord};
use crate::sync::group::{Fence, LockKind, MemberId};

pub(super) fn m(id: u64) -> MemberId {
    MemberId(id)
}

pub(super) fn init() -> LockRecord {
    apply(None, &Op::Init { value: vec![7] }).unwrap().0
}

pub(super) fn acquire(
    rec: &LockRecord,
    member: u64,
    nonce: u64,
    kind: LockKind,
) -> (LockRecord, OpOutcome) {
    apply(
        Some(rec),
        &Op::AcquireOrEnqueue {
            member: m(member),
            nonce,
            kind,
            no_enqueue: false,
        },
    )
    .unwrap()
}

#[test]
fn init_only_from_none() {
    let rec = init();
    assert_eq!(rec.value, vec![7]);
    assert_eq!(
        apply(Some(&rec), &Op::Init { value: vec![8] }).unwrap_err(),
        OpDenied::AlreadyInitialized
    );
    assert_eq!(
        apply(
            None,
            &Op::ClaimQueued {
                member: m(1),
                nonce: 1
            }
        )
        .unwrap_err(),
        OpDenied::Uninitialized
    );
}

#[test]
fn immediate_grant_then_fifo_enqueue() {
    let rec = init();
    let (rec, out) = acquire(&rec, 1, 10, LockKind::Write);
    let fence = match out {
        OpOutcome::Granted { fence, recovered } => {
            assert!(recovered.is_none());
            fence
        }
        other => panic!("expected grant, got {other:?}"),
    };
    assert_eq!(fence, Fence(1));

    // second writer queues; retry of the same request is idempotent
    let (rec, out) = acquire(&rec, 2, 20, LockKind::Write);
    assert_eq!(out, OpOutcome::Enqueued { position: 0 });
    let (rec, out) = acquire(&rec, 2, 20, LockKind::Write);
    assert_eq!(out, OpOutcome::Enqueued { position: 0 });

    // retry of the holder's own acquire returns the same grant
    let (_, out) = acquire(&rec, 1, 10, LockKind::Write);
    assert_eq!(
        out,
        OpOutcome::Granted {
            fence,
            recovered: None
        }
    );
}

#[test]
fn try_acquire_would_block() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let denied = apply(
        Some(&rec),
        &Op::AcquireOrEnqueue {
            member: m(2),
            nonce: 20,
            kind: LockKind::Write,
            no_enqueue: true,
        },
    )
    .unwrap_err();
    assert_eq!(denied, OpDenied::WouldBlock);
    assert!(rec.queue.is_empty());
}

#[test]
fn claim_respects_admission_and_liveness() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let (rec, _) = acquire(&rec, 2, 20, LockKind::Write);

    // not admissible while the holder lives
    assert_eq!(
        apply(
            Some(&rec),
            &Op::ClaimQueued {
                member: m(2),
                nonce: 20
            }
        )
        .unwrap_err(),
        OpDenied::NotAdmissible
    );
    // never-queued member cannot claim
    assert_eq!(
        apply(
            Some(&rec),
            &Op::ClaimQueued {
                member: m(3),
                nonce: 30
            }
        )
        .unwrap_err(),
        OpDenied::NotQueued
    );

    // after release, the head claims; fences strictly increase
    let (rec, _) = apply(
        Some(&rec),
        &Op::Release {
            member: m(1),
            nonce: 10,
            expect_fence: Fence(1),
            new_value: None,
        },
    )
    .unwrap();
    let (rec, out) = apply(
        Some(&rec),
        &Op::ClaimQueued {
            member: m(2),
            nonce: 20,
        },
    )
    .unwrap();
    assert!(matches!(out, OpOutcome::Granted { fence, .. } if fence == Fence(2)));
    assert!(rec.queue.is_empty());
}

#[test]
fn renew_is_idempotent_and_fenced() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let renew = |rec: &LockRecord, seq: u64| {
        apply(
            Some(rec),
            &Op::Renew {
                member: m(1),
                nonce: 10,
                expect_fence: Fence(1),
                expect_lease_seq: seq,
            },
        )
    };
    let (rec, out) = renew(&rec, 0).unwrap();
    assert_eq!(out, OpOutcome::Renewed { lease_seq: 1 });
    // replay of the same renew: accepted without double-increment
    let (rec, out) = renew(&rec, 0).unwrap();
    assert_eq!(out, OpOutcome::Renewed { lease_seq: 1 });
    // stale-by-two renews and wrong fences are denied
    assert!(matches!(
        apply(
            Some(&rec),
            &Op::Renew {
                member: m(1),
                nonce: 10,
                expect_fence: Fence(9),
                expect_lease_seq: 1
            }
        ),
        Err(OpDenied::NotHolder)
    ));
    let (rec, _) = renew(&rec, 1).unwrap();
    assert!(matches!(renew(&rec, 0), Err(OpDenied::NotHolder)));
}

#[test]
fn release_commits_value_atomically_and_replays() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let release = Op::Release {
        member: m(1),
        nonce: 10,
        expect_fence: Fence(1),
        new_value: Some(vec![42]),
    };
    let (rec, _) = apply(Some(&rec), &release).unwrap();
    assert_eq!(rec.value, vec![42]);
    assert_eq!(rec.value_version, Fence(1));
    assert_eq!(rec.holders, Holders::None);
    // replay after commit is recognized via value_version
    let (rec2, out) = apply(Some(&rec), &release).unwrap();
    assert_eq!(out, OpOutcome::Released);
    assert_eq!(rec2, rec);
    // value-less replay is recognized via the last_released tombstone
    let (rec3, out) = apply(
        Some(&rec),
        &Op::Release {
            member: m(1),
            nonce: 10,
            expect_fence: Fence(1),
            new_value: None,
        },
    )
    .unwrap();
    assert_eq!(out, OpOutcome::Released);
    assert_eq!(rec3, rec);
    // a stranger's release is still denied
    assert!(matches!(
        apply(
            Some(&rec),
            &Op::Release {
                member: m(9),
                nonce: 99,
                expect_fence: Fence(1),
                new_value: None
            }
        ),
        Err(OpDenied::NotHolder)
    ));
}
