//! Directed adversarial tests: each scenario mounts a specific attack on a safety
//! property — stale ballots, dueling proposers, forged accepts, stale steal snapshots,
//! fenced-out zombies, write-preference bypass, re-init, voter amnesia — and asserts
//! the protocol's defense. Pure and synchronous: no I/O, no clocks, no tokio.
use super::acceptor::{AcceptReply, Acceptor, PrepareReply};
use super::op_types::{Op, OpDenied, OpOutcome};
use super::ops::apply;
use super::record::{HolderEntry, Holders, LockRecord};
use super::wire::Ballot;
use super::{Fence, LockKind, MemberId};

const N: usize = 5;
const QUORUM: usize = N / 2 + 1;
const ALL: [usize; N] = [0, 1, 2, 3, 4];

fn ballot(counter: u64, member: u64) -> Ballot {
    Ballot {
        counter,
        proposer: MemberId(member),
    }
}

#[rustfmt::skip]
fn acquire(m: u64, nonce: u64, kind: LockKind, no_enqueue: bool) -> Op {
    Op::AcquireOrEnqueue { member: MemberId(m), nonce, kind, no_enqueue }
}
#[rustfmt::skip]
fn renew(m: u64, nonce: u64, f: Fence, s: u64) -> Op {
    Op::Renew { member: MemberId(m), nonce, expect_fence: f, expect_lease_seq: s }
}
#[rustfmt::skip]
fn release(m: u64, nonce: u64, f: Fence, v: Option<Vec<u8>>) -> Op {
    Op::Release { member: MemberId(m), nonce, expect_fence: f, new_value: v }
}
#[rustfmt::skip]
fn steal(t: u64, n: u64, f: Fence, s: u64) -> Op {
    Op::Steal { target: MemberId(t), target_nonce: n, expect_fence: f, expect_lease_seq: s }
}

/// Applies `ops` in order onto a freshly initialized record, unwrapping every step.
fn state(ops: &[Op]) -> LockRecord {
    let mut rec = apply(None, &Op::Init { value: vec![9] }).unwrap().0;
    for op in ops {
        rec = apply(Some(&rec), op).unwrap().0;
    }
    rec
}

fn writer(rec: &LockRecord) -> HolderEntry {
    match &rec.holders {
        Holders::Writer(h) => h.clone(),
        other => panic!("expected writer, got {other:?}"),
    }
}

struct Cluster(Vec<Acceptor>);

impl Cluster {
    fn new() -> Self {
        let mut c = Self(vec![Acceptor::default(); N]);
        let init = c.round(&ALL, ballot(1, 0), &Op::Init { value: vec![] });
        assert!(init.is_some(), "bootstrap init must commit");
        c
    }

    /// One CASPaxos round restricted to the acceptors in `q`; `None` = failed round.
    fn round(&mut self, q: &[usize], b: Ballot, op: &Op) -> Option<LockRecord> {
        let (mut votes, mut promised) = (0, Vec::new());
        for &i in q {
            if let PrepareReply::Promise { accepted } = self.0[i].on_prepare(b) {
                votes += 1;
                promised.extend(accepted);
            }
        }
        (votes >= QUORUM).then_some(())?;
        let base = promised
            .into_iter()
            .max_by_key(|(bb, _)| *bb)
            .map(|(_, r)| r);
        let rec = apply(base.as_ref(), op).ok()?.0;
        let mut acks = 0;
        for &i in q {
            let reply = self.0[i].on_accept(b, rec.clone());
            acks += matches!(reply, AcceptReply::Accepted) as usize;
        }
        (acks >= QUORUM).then_some(rec)
    }

    /// The record any future reader adopts: the highest-ballot accepted state.
    fn read(&self) -> LockRecord {
        let best = (0..N)
            .filter_map(|i| self.0[i].read_hint())
            .max_by_key(|(b, _)| *b);
        best.unwrap().1
    }
}

#[test]
fn stale_ballot_cannot_overwrite_committed_state() {
    let mut c = Cluster::new();
    let op = acquire(1, 10, LockKind::Write, false);
    let rec = c.round(&ALL, ballot(2, 1), &op).unwrap();
    // a laggard's lower-ballot prepare is refused by every voter
    for i in ALL {
        assert!(matches!(
            c.0[i].on_prepare(ballot(1, 4)),
            PrepareReply::Nack { .. }
        ));
    }
    // a forged direct accept below the promise is refused and changes nothing
    let forged = state(&[acquire(4, 99, LockKind::Write, false)]);
    for i in ALL {
        let reply = c.0[i].on_accept(ballot(1, 4), forged.clone());
        assert!(matches!(reply, AcceptReply::Nack { .. }));
    }
    assert_eq!(c.read(), rec);
}

#[test]
fn dueling_proposers_cannot_double_grant_write() {
    let mut c = Cluster::new();
    let (b1, b2) = (ballot(5, 1), ballot(6, 2));
    // P1 prepares on the left quorum only
    for i in [0, 1, 2] {
        assert!(matches!(
            c.0[i].on_prepare(b1),
            PrepareReply::Promise { .. }
        ));
    }
    // P2 runs a complete higher-ballot round on the right quorum and commits
    let won = c.round(&[2, 3, 4], b2, &acquire(2, 22, LockKind::Write, false));
    assert!(won.is_some());
    // P1, unaware, pushes its own conflicting write grant: the intersection voter
    // refuses, so P1 cannot reach quorum and its round dies
    let g1 = state(&[acquire(1, 11, LockKind::Write, false)]);
    let mut acks = 0;
    for i in [0, 1, 2] {
        acks += matches!(c.0[i].on_accept(b1, g1.clone()), AcceptReply::Accepted) as usize;
    }
    assert!(acks < QUORUM, "stale accept must be refused");
    // every reader adopts P2's grant; P1's phantom write is unreachable
    let fin = c.read();
    assert!(matches!(&fin.holders, Holders::Writer(h) if h.member == MemberId(2)));
    assert!(fin.holder(MemberId(1), 11).is_none());
    assert!(fin.wait_entry(MemberId(1), 11).is_none());
}

#[test]
fn steal_with_stale_snapshot_is_rejected() {
    let w = acquire(1, 10, LockKind::Write, false);
    let h = writer(&state(std::slice::from_ref(&w)));
    // the holder proves liveness by renewing; the attacker's frozen snapshot is stale
    let rec = state(&[w, renew(1, 10, h.fence, 0)]);
    let denied = apply(Some(&rec), &steal(1, 10, h.fence, 0)).unwrap_err();
    assert_eq!(denied, OpDenied::SnapshotMismatch);
    // a current snapshot (genuinely dead holder) still succeeds
    assert!(apply(Some(&rec), &steal(1, 10, h.fence, 1)).is_ok());
}

#[test]
fn stolen_writer_is_fully_fenced_out() {
    let w = acquire(1, 10, LockKind::Write, false);
    let base = state(std::slice::from_ref(&w));
    let h = writer(&base);
    let (rec, out) = apply(Some(&base), &steal(1, 10, h.fence, 0)).unwrap();
    assert_eq!(out, OpOutcome::Stolen);
    assert!(rec.poisoned.is_some());
    // the victim's renew and mutating release are refused; its value never publishes
    let d1 = apply(Some(&rec), &renew(1, 10, h.fence, 0)).unwrap_err();
    let d2 = apply(Some(&rec), &release(1, 10, h.fence, Some(vec![0xEE]))).unwrap_err();
    assert_eq!((d1, d2), (OpDenied::NotHolder, OpDenied::NotHolder));
    assert_eq!(rec.value_version, Fence(0));
    // the next write grant reports the recovered poison exactly, then clears it
    let (rec2, out2) = apply(Some(&rec), &acquire(2, 20, LockKind::Write, false)).unwrap();
    let ok = matches!(&out2, OpOutcome::Granted { recovered: Some(p), .. }
        if p.member == MemberId(1) && p.fence == h.fence);
    assert!(ok, "got {out2:?}");
    assert!(rec2.poisoned.is_none());
}

#[test]
fn write_preference_cannot_be_bypassed_by_readers() {
    // a reader holds and a writer queues; later readers must not sneak past it
    let rec = state(&[
        acquire(1, 1, LockKind::Read, false),
        acquire(2, 2, LockKind::Write, false),
    ]);
    let d = apply(Some(&rec), &acquire(3, 3, LockKind::Read, true)).unwrap_err();
    assert_eq!(d, OpDenied::WouldBlock);
    let (rec, out) = apply(Some(&rec), &acquire(3, 3, LockKind::Read, false)).unwrap();
    assert!(matches!(out, OpOutcome::Enqueued { .. }));
    // claiming ahead of the queued writer is inadmissible
    let claim = Op::ClaimQueued {
        member: MemberId(3),
        nonce: 3,
    };
    assert_eq!(
        apply(Some(&rec), &claim).unwrap_err(),
        OpDenied::NotAdmissible
    );
}

#[test]
fn reinit_cannot_reset_the_lock() {
    let rec = state(&[acquire(1, 10, LockKind::Write, false)]);
    let denied = apply(Some(&rec), &Op::Init { value: vec![] }).unwrap_err();
    assert_eq!(denied, OpDenied::AlreadyInitialized);
}

#[test]
fn cancel_replay_cannot_double_restore_poison() {
    // member2's write grant consumed the poison left by stealing member1
    let w1 = acquire(1, 10, LockKind::Write, false);
    let f1 = writer(&state(std::slice::from_ref(&w1))).fence;
    let w2 = acquire(2, 20, LockKind::Write, false);
    let rec = state(&[w1, steal(1, 10, f1, 0), w2]);
    // cancel-races-grant: the dequeue revokes the grant and restores the poison once
    let dq = Op::Dequeue {
        member: MemberId(2),
        nonce: 20,
    };
    let (rec, out) = apply(Some(&rec), &dq).unwrap();
    assert_eq!(out, OpOutcome::Dequeued { was_granted: true });
    assert_eq!(rec.poisoned.as_ref().map(|p| p.member), Some(MemberId(1)));
    // replaying the cancel is inert: no double restore, no state change
    assert_eq!(apply(Some(&rec), &dq).unwrap_err(), OpDenied::NotQueued);
}

/// Executable form of the `EphemeralAcceptorStore` warning: a voter restarting with
/// amnesia re-promises below its earlier promise (breaking quorum intersection under
/// crash-RECOVERY), while restoring the persisted snapshot preserves monotonicity —
/// exactly what a durable `AcceptorStateStore` (write-before-reply) exists for.
#[test]
fn amnesiac_voter_forgets_promises_but_persisted_state_does_not() {
    let mut acc = Acceptor::default();
    acc.on_prepare(ballot(5, 1));
    let saved = acc.state().clone();
    let mut amnesiac = Acceptor::default(); // crash + restart without persistence
    assert!(matches!(
        amnesiac.on_prepare(ballot(3, 2)),
        PrepareReply::Promise { .. }
    ));
    let mut restored = Acceptor::from_persisted(saved);
    assert!(matches!(
        restored.on_prepare(ballot(3, 2)),
        PrepareReply::Nack { .. }
    ));
}
