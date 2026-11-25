use super::*;
use crate::proto::peer::group_log_plan::*;
use std::time::Duration;

const OWNER: u64 = 1;

fn key() -> MessageGroupKey {
    MessageGroupKey::new(OWNER, 7)
}

fn limits() -> GroupLogLimits {
    GroupLogLimits {
        max_age: Duration::from_secs(60),
        max_messages: 3,
        max_bytes: 1_000_000,
        max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES,
    }
}

/// Decides and commits one broadcast, as the fan-out does once its persistence is done.
fn send(book: &mut GroupOrderBook, id: Option<(u64, GroupMessageId)>) -> Next {
    let next = book.next(key(), OWNER, id, &digest(b"frame"));
    book.commit(key(), &next, id, 10, 0);
    next
}

fn seq(next: &Next) -> u64 {
    match next {
        Next::New { position, .. } | Next::Retry { position } => position.seq,
    }
}

#[test]
fn positions_run_from_one_without_gaps() {
    let mut book = GroupOrderBook::default();
    let seqs: Vec<u64> = (0..5).map(|_| seq(&send(&mut book, None))).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

#[test]
fn an_uncommitted_decision_uses_no_number() {
    let mut book = GroupOrderBook::default();
    // A decision whose write failed is never committed: the next one takes the same number.
    let failed = book.next(key(), OWNER, None, &digest(b"lost"));
    assert_eq!(seq(&failed), 1);
    assert_eq!(seq(&send(&mut book, None)), 1);
}

#[test]
fn a_retried_message_keeps_its_position() {
    let mut book = GroupOrderBook::default();
    let id = Some((2, GroupMessageId([9; 16])));
    let first = send(&mut book, id);
    let _ = send(&mut book, None);
    let again = book.next(key(), OWNER, id, &digest(b"frame"));
    assert_eq!(
        again,
        Next::Retry {
            position: match first {
                Next::New { position, .. } => position,
                _ => unreachable!(),
            }
        }
    );
    // Another sender's message with the same id is its own message.
    let other = send(&mut book, Some((3, GroupMessageId([9; 16]))));
    assert_eq!(seq(&other), 3);
}

#[test]
fn a_group_without_replay_reserves_its_numbers_in_blocks() {
    let mut book = GroupOrderBook::default();
    let first = book.next(key(), OWNER, None, &digest(b"f"));
    assert!(matches!(
        first,
        Next::New {
            persist: Persist::Reserve(RESERVE_BLOCK),
            ..
        }
    ));
    book.commit(key(), &first, None, 1, 0);
    for _ in 1..RESERVE_BLOCK {
        let next = send(&mut book, None);
        assert!(matches!(
            next,
            Next::New {
                persist: Persist::Nothing,
                ..
            }
        ));
    }
    let past = book.next(key(), OWNER, None, &digest(b"f"));
    assert!(
        matches!(past, Next::New { persist: Persist::Reserve(r), .. } if r == 2 * RESERVE_BLOCK)
    );
}

#[test]
fn a_replay_group_logs_every_position_and_chains_them() {
    let mut book = GroupOrderBook::default();
    let _ = send(&mut book, None);
    let since = book.order_mut(key(), OWNER).enable_replay(limits());
    assert_eq!(since, Some(2));
    let a = book.next(key(), OWNER, None, &digest(b"a"));
    let b_after_a = {
        book.commit(key(), &a, None, 10, 0);
        book.next(key(), OWNER, None, &digest(b"b"))
    };
    let (
        Next::New {
            position: pa,
            persist: Persist::Log,
        },
        Next::New { position: pb, .. },
    ) = (&a, &b_after_a)
    else {
        panic!("a replay group logs: {a:?}");
    };
    assert_eq!((pa.seq, pb.seq), (2, 3));
    assert_eq!(
        pb.chain,
        Some(chain_link(key(), 3, &pa.chain.unwrap(), &digest(b"b")))
    );
    assert_ne!(pa.chain, pb.chain);
}

#[test]
fn a_changed_frame_changes_the_chain() {
    let prev = [0u8; 32];
    assert_ne!(
        chain_link(key(), 1, &prev, &digest(b"a")),
        chain_link(key(), 1, &prev, &digest(b"b"))
    );
    assert_ne!(
        chain_link(key(), 1, &prev, &digest(b"a")),
        chain_link(key(), 2, &prev, &digest(b"a"))
    );
}

#[test]
fn the_log_is_kept_within_its_limits_and_says_where_it_starts() {
    let mut book = GroupOrderBook::default();
    let _ = book.order_mut(key(), OWNER).enable_replay(limits());
    for _ in 0..5 {
        let _ = send(&mut book, None);
    }
    let order = book.groups.get_mut(&key()).unwrap();
    let (dropped, through) = order.replay.as_ref().unwrap().over_limits(0).unwrap();
    assert_eq!((dropped, through), (vec![1, 2], 2));
    order.trimmed(through);
    let log = order.replay.as_ref().unwrap();
    assert_eq!(
        log.range(order.head, 0, u64::MAX, 10),
        Range::Trimmed { earliest: 3 }
    );
    assert_eq!(
        log.range(order.head, 2, u64::MAX, 10),
        Range::Seqs(vec![3, 4, 5])
    );
    assert_eq!(log.range(order.head, 3, 4, 10), Range::Seqs(vec![4]));
    assert_eq!(log.range(order.head, 5, u64::MAX, 10), Range::Seqs(vec![]));
    assert_eq!(
        log.range(order.head, 2, u64::MAX, 2),
        Range::Seqs(vec![3, 4])
    );
}

#[test]
fn entries_older_than_the_log_keeps_are_dropped() {
    let mut book = GroupOrderBook::default();
    let _ = book.order_mut(key(), OWNER).enable_replay(limits());
    let _ = send(&mut book, None);
    let log = book.groups[&key()].replay.clone().unwrap();
    assert_eq!(log.over_limits(0), None);
    let later = i64::try_from(Duration::from_secs(61).as_nanos()).unwrap();
    assert_eq!(log.over_limits(later), Some((vec![1], 1)));
}

#[test]
fn a_member_from_before_replay_starts_at_since() {
    let mut book = GroupOrderBook::default();
    for _ in 0..4 {
        let _ = send(&mut book, None);
    }
    let order = book.order_mut(key(), OWNER);
    assert_eq!(order.enable_replay(limits()), Some(5));
    assert_eq!(order.enable_replay(limits()), None);
    let _ = send(&mut book, None);
    let order = &book.groups[&key()];
    let log = order.replay.as_ref().unwrap();
    assert_eq!(log.range(order.head, 1, u64::MAX, 10), Range::Seqs(vec![5]));
}
