//! The outbox (§7): moves, never copies; wipes exactly what it discards; and on a true close
//! returns, in send order, exactly what was never seen delivered.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use citadel_link::outbox::{Grade, LinkOutbox, Payload, PayloadLane, Seq};
use citadel_link::{ConnectionId, Incarnation, Ticket};
use proptest::prelude::*;

/// A payload that records when it is wiped. Not `Clone`, like every payload the outbox holds.
#[derive(Debug)]
struct Sentinel {
    id: u128,
    bytes: Vec<u8>,
    wiped: Rc<RefCell<Vec<u128>>>,
}

impl Payload for Sentinel {
    fn byte_len(&self) -> usize {
        self.bytes.len()
    }
    fn wipe(&mut self) {
        self.bytes.fill(0);
        self.wiped.borrow_mut().push(self.id);
    }
}

fn inc(n: u32) -> Incarnation {
    Incarnation {
        connection: ConnectionId(1),
        n,
    }
}

#[derive(Clone, Debug)]
enum Op {
    Push(usize),
    Write(u32),
    Flush(usize),
    Ack(usize),
    Lost(u32),
    Acknowledging(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (1usize..64).prop_map(Op::Push),
        3 => (1u32..4).prop_map(Op::Write),
        3 => any::<usize>().prop_map(Op::Flush),
        3 => any::<usize>().prop_map(Op::Ack),
        1 => (1u32..4).prop_map(Op::Lost),
        1 => any::<bool>().prop_map(Op::Acknowledging),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_048, ..ProptestConfig::default() })]

    #[test]
    fn a_close_returns_exactly_the_undelivered_in_order(ops in prop::collection::vec(op(), 0..80)) {
        let wiped = Rc::new(RefCell::new(Vec::new()));
        let mut outbox = LinkOutbox::new(1024, true);
        let mut accepted = BTreeSet::new();
        let mut acked = BTreeSet::new();
        let mut seqs: Vec<(Seq, u128)> = Vec::new();
        let mut written: BTreeSet<(Seq, u32)> = BTreeSet::new();
        let mut next = 0u128;
        for op in ops {
            match op {
                Op::Push(len) => {
                    next += 1;
                    let payload = Sentinel { id: next, bytes: vec![0xAB; len], wiped: wiped.clone() };
                    match outbox.push(Ticket(next), PayloadLane::Message, payload) {
                        Ok(seq) => { accepted.insert(next); seqs.push((seq, next)); }
                        Err(refused) => {
                            prop_assert_eq!(refused.ticket, Ticket(next));
                            prop_assert!(refused.payload.bytes.iter().all(|b| *b == 0xAB), "returned intact");
                        }
                    }
                }
                Op::Write(n) => {
                    for seq in outbox.take_writes(inc(n)) {
                        prop_assert!(written.insert((seq, n)), "{seq:?} written twice to {n}");
                    }
                }
                Op::Flush(i) if !seqs.is_empty() => { outbox.flushed(seqs[i % seqs.len()].0); }
                Op::Ack(i) if !seqs.is_empty() => {
                    let (seq, id) = seqs[i % seqs.len()];
                    if outbox.acked(seq) { acked.insert(id); }
                }
                Op::Lost(n) => {
                    outbox.path_lost(inc(n));
                    written.retain(|(_, m)| *m != n);
                }
                Op::Acknowledging(on) => outbox.set_acknowledging(on),
                _ => {}
            }
            prop_assert!(outbox.used_bytes() <= 1024);
        }
        let drained = outbox.drain();
        let undelivered: Vec<u128> = drained.undelivered.iter().map(|u| u.ticket.0).collect();
        let order: Vec<Seq> = drained.undelivered.iter().map(|u| u.seq).collect();
        prop_assert!(order.windows(2).all(|p| p[0] < p[1]), "send order");
        let possibly: BTreeSet<u128> = drained.possibly_delivered.iter().map(|t| t.0).collect();
        let mut all: Vec<u128> = undelivered.clone();
        all.extend(&possibly);
        all.extend(&acked);
        all.sort();
        prop_assert_eq!(all, accepted.iter().copied().collect::<Vec<_>>(), "each accepted send is in exactly one place");
        prop_assert_eq!(drained.acked as usize, acked.len());
        let mut wiped_ids = wiped.borrow().clone();
        wiped_ids.sort();
        let mut discarded: Vec<u128> = possibly.iter().chain(acked.iter()).copied().collect();
        discarded.sort();
        prop_assert_eq!(wiped_ids, discarded, "wiped exactly the discarded, each once");
        prop_assert!(drained.undelivered.iter().all(|u| u.payload.bytes.iter().all(|b| *b == 0xAB)), "returned plaintext untouched");
    }
}

#[test]
fn over_budget_is_refused_with_the_payload_not_dropped() {
    let wiped = Rc::new(RefCell::new(Vec::new()));
    let mut outbox = LinkOutbox::new(10, false);
    let small = Sentinel {
        id: 1,
        bytes: vec![1; 8],
        wiped: wiped.clone(),
    };
    let big = Sentinel {
        id: 2,
        bytes: vec![2; 8],
        wiped: wiped.clone(),
    };
    assert!(outbox.push(Ticket(1), PayloadLane::Message, small).is_ok());
    let refused = outbox
        .push(Ticket(2), PayloadLane::Message, big)
        .unwrap_err();
    assert_eq!(
        (refused.ticket, refused.payload.bytes.len()),
        (Ticket(2), 8)
    );
    assert_eq!(outbox.drain().over_budget_bytes, 8);
    assert!(wiped.borrow().is_empty());
}

#[test]
fn a_flush_without_acknowledgement_wipes_and_keeps_only_the_ticket() {
    let wiped = Rc::new(RefCell::new(Vec::new()));
    let mut outbox = LinkOutbox::new(100, false);
    let seq = outbox
        .push(
            Ticket(5),
            PayloadLane::Message,
            Sentinel {
                id: 5,
                bytes: vec![9; 4],
                wiped: wiped.clone(),
            },
        )
        .unwrap();
    assert!(!outbox.flushed(seq), "not written yet");
    assert_eq!(outbox.take_writes(inc(1)), [seq]);
    assert!(
        outbox.take_writes(inc(1)).is_empty(),
        "marked before it is returned"
    );
    assert!(outbox.flushed(seq));
    assert_eq!(*wiped.borrow(), [5]);
    assert_eq!(outbox.used_bytes(), 0);
    let drained = outbox.drain();
    assert_eq!(drained.possibly_delivered, [Ticket(5)]);
    assert!(drained.undelivered.is_empty());
}

#[test]
fn a_lost_path_requeues_what_was_unacknowledged_for_the_next_incarnation() {
    let wiped = Rc::new(RefCell::new(Vec::new()));
    let mut outbox = LinkOutbox::new(100, true);
    let seqs: Vec<_> = (1..=3)
        .map(|i| {
            let p = Sentinel {
                id: i,
                bytes: vec![1],
                wiped: wiped.clone(),
            };
            outbox.push(Ticket(i), PayloadLane::Message, p).unwrap()
        })
        .collect();
    assert_eq!(outbox.take_writes(inc(1)), seqs);
    assert!(outbox.flushed(seqs[0]));
    assert!(outbox.acked(seqs[1]));
    outbox.path_lost(inc(1));
    assert_eq!(outbox.grade(seqs[0]), Some(Grade::Queued));
    assert_eq!(
        outbox.take_writes(inc(2)),
        [seqs[0], seqs[2]],
        "replayed in order, the acked one never"
    );
    let drained = outbox.drain();
    assert!(drained.undelivered.iter().all(|u| u.possibly_seen));
    assert_eq!(drained.acked, 1);
}
