//! Table tests for apply() idempotent-replay branches (ambiguous committed rounds).

use super::ops_tests::{acquire, init, m};
use crate::sync::group::op_types::{Op, OpOutcome};
use crate::sync::group::ops::apply;
use crate::sync::group::{Fence, LockKind};

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
