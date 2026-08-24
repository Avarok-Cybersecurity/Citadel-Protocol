//! Table tests for apply() idempotent-replay branches (ambiguous committed rounds).

use super::ops_tests::{acquire, init, m};
use crate::sync::group::op_types::{Op, OpDenied, OpOutcome};
use crate::sync::group::ops::apply;
use crate::sync::group::{Fence, LockKind};

fn release(member: u64, nonce: u64, fence: u64, value: Option<Vec<u8>>) -> Op {
    Op::Release {
        member: m(member),
        nonce,
        expect_fence: Fence(fence),
        new_value: value,
    }
}

#[test]
fn downgrade_replay_is_idempotent() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let op = Op::Downgrade {
        member: m(1),
        nonce: 10,
        expect_fence: Fence(1),
        new_value: Some(vec![9]),
    };
    let (rec, out) = apply(Some(&rec), &op).unwrap();
    assert_eq!(out, OpOutcome::Downgraded { fence: Fence(2) });
    // replay after an ambiguous committed round: same fence, no re-mint, no re-write
    let (rec2, out) = apply(Some(&rec), &op).unwrap();
    assert_eq!(out, OpOutcome::Downgraded { fence: Fence(2) });
    assert_eq!(rec2, rec);
}

/// Regression (CI flake `mutex_contended_counter_n3`, `Stolen { fence: Fence(1) }`):
/// member 1's release COMMITTED but its round looked ambiguous (accept-nack from a
/// dueling proposer), so it was replayed — after member 2 had already been granted
/// and had released, overwriting the old single-slot tombstone. The replay must be
/// recognized as idempotent success, not misreported as `NotHolder` -> `Stolen`.
#[test]
fn release_replay_survives_interleaved_releases_by_other_members() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let rel1 = release(1, 10, 1, Some(vec![1]));
    let (rec, _) = apply(Some(&rec), &rel1).unwrap();
    let (rec, _) = acquire(&rec, 2, 20, LockKind::Write);
    let (rec, _) = apply(Some(&rec), &release(2, 20, 2, Some(vec![2]))).unwrap();
    // member 1's delayed replay: idempotent success, zero state change
    let (rec2, out) = apply(Some(&rec), &rel1).unwrap();
    assert_eq!(out, OpOutcome::Released);
    assert_eq!(rec2, rec);
    assert_eq!(
        rec2.value,
        vec![2],
        "replay must not resurrect the old value"
    );
}

/// The per-member tombstone must not weaken fencing: a genuinely STOLEN grant's
/// release stays denied even after other members' releases commit in between.
#[test]
fn stolen_release_stays_denied_after_interleaved_releases() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let steal = Op::Steal {
        target: m(1),
        target_nonce: 10,
        expect_fence: Fence(1),
        expect_lease_seq: 0,
    };
    let (rec, _) = apply(Some(&rec), &steal).unwrap();
    let (rec, _) = acquire(&rec, 2, 20, LockKind::Write); // consumes the poison
    let (rec, _) = apply(Some(&rec), &release(2, 20, 2, Some(vec![2]))).unwrap();
    let denied = apply(Some(&rec), &release(1, 10, 1, Some(vec![0xEE]))).unwrap_err();
    assert_eq!(denied, OpDenied::NotHolder);
    assert_eq!(rec.value, vec![2], "victim's value must never publish");
}

/// A member's tombstone tracks only its MOST RECENT release: the current release
/// replays idempotently, while a pre-previous one (impossible for a live proposer,
/// which awaits each release before the next acquire) stays denied.
#[test]
fn tombstone_is_per_member_most_recent_release() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Write);
    let (rec, _) = apply(Some(&rec), &release(1, 10, 1, None)).unwrap();
    let (rec, _) = acquire(&rec, 1, 11, LockKind::Write);
    let (rec, _) = apply(Some(&rec), &release(1, 11, 2, None)).unwrap();
    let (_, out) = apply(Some(&rec), &release(1, 11, 2, None)).unwrap();
    assert_eq!(out, OpOutcome::Released);
    assert_eq!(
        apply(Some(&rec), &release(1, 10, 1, None)).unwrap_err(),
        OpDenied::NotHolder
    );
}

#[test]
fn read_release_replay_is_idempotent_via_tombstone() {
    let rec = init();
    let (rec, _) = acquire(&rec, 1, 10, LockKind::Read);
    let op = Op::Release {
        member: m(1),
        nonce: 10,
        expect_fence: Fence(1),
        new_value: None,
    };
    let (rec, out) = apply(Some(&rec), &op).unwrap();
    assert_eq!(out, OpOutcome::Released);
    let (rec2, out) = apply(Some(&rec), &op).unwrap();
    assert_eq!(out, OpOutcome::Released);
    assert_eq!(rec2, rec);
}
