//! Deterministic seeded protocol simulator: N pure acceptors + a synchronous CASPaxos
//! proposer, inline xorshift64 RNG (no I/O, no clocks). Invariants panic with the seed.
use super::acceptor::{AcceptReply, Acceptor, PrepareReply};
use super::op_types::{Op, OpDenied, OpOutcome};
use super::ops::apply;
use super::record::{HolderEntry, Holders, LockRecord};
use super::wire::Ballot;
use super::{admission, Fence, LockKind, MemberId};
use std::collections::HashMap;

const N: usize = 5;
const QUORUM: usize = N / 2 + 1;

type Rec = LockRecord;
type RoundResult = Result<(Rec, OpOutcome), OpDenied>;

#[derive(Default)]
struct Belief {
    held: Option<(u64, LockKind, Fence, u64)>, // (nonce, kind, fence, lease_seq)
    queued: Option<(u64, LockKind)>,
}
impl Belief {
    fn grant(&mut self, nonce: u64, kind: LockKind, fence: Fence) {
        self.queued = None;
        self.held = Some((nonce, kind, fence, 0));
    }
}
fn holders(rec: &Rec) -> &[HolderEntry] {
    match &rec.holders {
        Holders::None => &[],
        Holders::Writer(h) => std::slice::from_ref(h),
        Holders::Readers(hs) => hs,
    }
}

#[derive(Default)]
struct Sim {
    seed: u64,
    step: usize,
    rng: u64,
    acceptors: Vec<Acceptor>,
    beliefs: Vec<Belief>,
    reachable: [bool; N],
    counter: u64,
    next_nonce: u64,
    max_fence: u64,
    max_vv: u64,
    committed: HashMap<Ballot, Rec>,
}

impl Sim {
    #[allow(clippy::field_reassign_with_default)]
    fn new(seed: u64) -> Self {
        let mut s = Self::default();
        (s.seed, s.rng) = (seed, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        s.acceptors = vec![Acceptor::default(); N];
        s.beliefs = (0..N).map(|_| Belief::default()).collect();
        s.reachable = [true; N];
        s
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// One synchronous CASPaxos round against the reachable subset: majority promises,
    /// apply on the max-ballot promised record, majority acks. `None` = failed round.
    fn propose(&mut self, proposer: MemberId, op: &Op) -> Option<RoundResult> {
        let reach = self.reachable;
        reach[proposer.0 as usize].then_some(())?;
        self.counter += 1;
        let counter = self.counter;
        let ballot = Ballot { counter, proposer };
        let (mut votes, mut promised) = (0, Vec::new());
        for i in (0..N).filter(|i| reach[*i]) {
            if let PrepareReply::Promise { accepted } = self.acceptors[i].on_prepare(ballot) {
                votes += 1;
                promised.extend(accepted);
            }
        }
        (votes >= QUORUM).then_some(())?;
        let base = promised.into_iter().max_by_key(|(b, _)| *b).map(|(_, r)| r);
        let (rec, res) = match apply(base.as_ref(), op) {
            Ok((rec, out)) => (rec, Ok(out)),
            Err(d) => (base.clone()?, Err(d)), // identity write linearizes denials
        };
        let mut acks = 0;
        for i in (0..N).filter(|i| reach[*i]) {
            let reply = self.acceptors[i].on_accept(ballot, rec.clone());
            acks += matches!(reply, AcceptReply::Accepted) as usize;
        }
        (acks >= QUORUM).then_some(())?; // ambiguous rounds may still commit later
        if let Some(prev) = self.committed.insert(ballot, rec.clone()) {
            assert_eq!(&prev, &rec, "seed {}: ballot reuse", self.seed);
        }
        self.check(base.as_ref(), op, &rec, res.as_ref().ok());
        Some(res.map(|out| (rec, out)))
    }

    /// Safety invariants over the committed transition `pre -> new` caused by `op`.
    fn check(&mut self, pre: Option<&Rec>, op: &Op, new: &Rec, o: Option<&OpOutcome>) {
        let c = format!("seed={} step={}", self.seed, self.step);
        let mut ids: Vec<_> = new.queue.iter().map(|w| (w.member, w.nonce)).collect();
        ids.extend(holders(new).iter().map(|h| (h.member, h.nonce)));
        let rdrs_ok = !matches!(&new.holders, Holders::Readers(hs) if hs.is_empty());
        assert!(rdrs_ok, "{c}: empty Readers");
        ids.sort_unstable();
        assert!(ids.windows(2).all(|w| w[0] != w[1]), "{c}: dup entry");
        let Some(out) = o else { return }; // denial = identity write: structure only
        if let OpOutcome::Granted { fence, .. } | OpOutcome::Downgraded { fence } = out {
            if pre != Some(new) {
                assert!(fence.0 > self.max_fence, "{c}: stale fence {fence:?}");
                self.max_fence = fence.0;
            }
        }
        let bvv = pre.map_or(0, |r| r.value_version.0);
        if new.value_version.0 != bvv {
            let ok = matches!(op, Op::Release { new_value: Some(_), expect_fence, .. }
                | Op::Downgrade { new_value: Some(_), expect_fence, .. }
                if new.value_version == *expect_fence);
            assert!(ok && new.value_version.0 > bvv, "{c}: bad vv via {op:?}");
        }
        assert!(new.value_version.0 >= self.max_vv, "{c}: vv regressed");
        self.max_vv = new.value_version.0;
        if let (Op::ClaimQueued { member, nonce }, OpOutcome::Granted { .. }) = (op, out) {
            if let Some(b) = pre.filter(|b| b.wait_entry(*member, *nonce).is_some()) {
                assert!(admission::is_admissible(b, *member, *nonce), "{c}: fifo");
            }
        }
        match (pre.and_then(|r| r.poisoned.as_ref()), &new.poisoned) {
            (None, Some(_)) => {
                let steal = matches!(op, Op::Steal { target, target_nonce, .. }
                    if matches!(pre.map(|r| &r.holders), Some(Holders::Writer(h))
                        if h.member == *target && h.nonce == *target_nonce));
                let deq = matches!(out, OpOutcome::Dequeued { was_granted: true });
                assert!(steal || deq, "{c}: poison set by {op:?}");
            }
            (Some(p), None) => assert!(
                matches!(out, OpOutcome::Granted { recovered: Some(r), .. } if r == p),
                "{c}: poison cleared by {op:?}"
            ),
            (Some(a), Some(b)) => assert_eq!(a, b, "{c}: poison replaced by {op:?}"),
            _ => {}
        }
    }

    #[rustfmt::skip] // dense op-construction table reads better unwrapped
    fn gen_op(&mut self, m: usize) -> Op {
        let member = MemberId(m as u64);
        if let Some((nonce, kind, expect_fence, expect_lease_seq)) = self.beliefs[m].held {
            let w = kind == LockKind::Write;
            let new_value = (w && self.rand() & 1 == 0).then(|| vec![m as u8]);
            return match self.rand() % 6 {
                0 | 1 => Op::Renew { member, nonce, expect_fence, expect_lease_seq },
                2 if w => Op::Downgrade { member, nonce, expect_fence, new_value },
                _ => Op::Release { member, nonce, expect_fence, new_value },
            };
        }
        if let Some((nonce, _)) = self.beliefs[m].queued {
            return match self.rand() % 6 {
                0 => Op::RefreshWait { member, nonce },
                1 => Op::Dequeue { member, nonce },
                _ => Op::ClaimQueued { member, nonce },
            };
        }
        if let Some(op) = self.rand().is_multiple_of(4).then(|| self.disrupt(m)).flatten() {
            return op;
        }
        self.next_nonce += 1;
        let kind = [LockKind::Read, LockKind::Write][(self.rand() & 1) as usize];
        let (nonce, no_enqueue) = (self.next_nonce, self.rand().is_multiple_of(4));
        Op::AcquireOrEnqueue { member, nonce, kind, no_enqueue }
    }

    /// Steal a holder / evict a waiter from the local voter's accepted-state hint.
    #[rustfmt::skip]
    fn disrupt(&mut self, m: usize) -> Option<Op> {
        let (_, seen) = self.acceptors[m].read_hint()?;
        if self.rand() & 1 == 0 {
            let hs = holders(&seen);
            let h = hs.get((self.rand() % hs.len().max(1) as u64) as usize)?;
            let (target, target_nonce) = (h.member, h.nonce);
            let (f, s) = (h.fence, h.lease_seq);
            Some(Op::Steal { target, target_nonce, expect_fence: f, expect_lease_seq: s })
        } else {
            let w = seen.queue.get((self.rand() % seen.queue.len().max(1) as u64) as usize)?;
            let (target, target_nonce) = (w.member, w.nonce);
            Some(Op::EvictWaiter { target, target_nonce, expect_refresh_seq: w.refresh_seq })
        }
    }

    fn absorb(&mut self, m: usize, op: &Op, res: &Option<RoundResult>) {
        use super::op_types::Op::{AcquireOrEnqueue as Acq, ClaimQueued as Claim, *};
        use super::op_types::OpOutcome::{Downgraded as D, Granted as G, *};
        use super::LockKind::Read;
        let b = &mut self.beliefs[m];
        let out = match res {
            Some(Ok((_, out))) => out,
            Some(Err(OpDenied::NotHolder)) => return b.held = None, // stolen: forget it
            Some(Err(OpDenied::NotQueued)) if matches!(op, Claim { .. } | Dequeue { .. }) => {
                return b.queued = None; // evicted: forget the wait entry
            }
            _ => return, // failed round or benign denial: no new knowledge
        };
        match (op, out) {
            (Acq { nonce, kind, .. }, G { fence, .. }) => b.grant(*nonce, *kind, *fence),
            (Acq { nonce, kind, .. }, Enqueued { .. }) => b.queued = Some((*nonce, *kind)),
            (Claim { nonce, .. }, G { fence, .. }) => {
                let k = b.queued.take().map_or(LockKind::Write, |(_, k)| k);
                b.grant(*nonce, k, *fence);
            }
            (Renew { .. }, Renewed { lease_seq }) => b.held.as_mut().unwrap().3 = *lease_seq,
            (Release { .. }, Released) => b.held = None,
            (Downgrade { nonce, .. }, D { fence, .. }) => b.grant(*nonce, Read, *fence),
            (Dequeue { .. }, Dequeued { .. }) => (b.held, b.queued) = (None, None),
            _ => {}
        }
    }

    fn run(mut self, steps: usize) {
        let init = self.propose(MemberId(0), &Op::Init { value: vec![0] });
        let ok = matches!(init, Some(Ok((_, OpOutcome::Initialized))));
        assert!(ok, "seed {}: init round must commit", self.seed);
        for step in 1..=steps {
            self.step = step;
            let m = (self.rand() % N as u64) as usize;
            if self.rand() % 10 < 2 {
                self.reachable[m] = !self.reachable[m]; // partition toggle
                continue;
            }
            let op = self.gen_op(m);
            let res = self.propose(MemberId(m as u64), &op);
            self.absorb(m, &op, &res);
        }
    }
}

#[test]
fn seeded_protocol_simulation() {
    (1..=200).for_each(|seed| Sim::new(seed).run(300));
}

#[test]
#[ignore = "stress schedule (~10s): cargo test -p netbeam sim_tests -- --ignored"]
fn seeded_protocol_simulation_stress() {
    (1..=2000).for_each(|seed| Sim::new(seed).run(3000));
}
