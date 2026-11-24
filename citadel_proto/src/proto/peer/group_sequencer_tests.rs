use super::*;

const OWNER: u64 = 1;

fn key() -> MessageGroupKey {
    MessageGroupKey::new(OWNER, 7)
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
