use super::*;
use citadel_types::proto::GroupPosition;

const KEY: MessageGroupKey = MessageGroupKey { cid: 1, mgid: 2 };

#[test]
fn a_position_is_delivered_once_per_member_and_group() {
    let mut delivered = GroupDelivered::default();
    assert!(delivered.first_time(5, KEY, 1));
    assert!(delivered.first_time(5, KEY, 3), "numbers may skip");
    assert!(!delivered.first_time(5, KEY, 3));
    assert!(!delivered.first_time(5, KEY, 2), "and never go back");
    assert!(
        delivered.first_time(6, KEY, 1),
        "another member's count is its own"
    );
    let other = MessageGroupKey { cid: 1, mgid: 3 };
    assert!(delivered.first_time(5, other, 1), "as is another group's");
}

fn at(seq: u64) -> (GroupPosition, GroupBroadcast) {
    let position = GroupPosition {
        seq,
        chain: Some([seq as u8; 32]),
    };
    (position, GroupBroadcast::GroupNonExists { key: KEY })
}

fn arrive(delivered: &mut GroupDelivered, seq: u64) -> Arrival {
    let (position, frame) = at(seq);
    delivered.arrive(5, KEY, position, frame, false)
}

fn seqs(arrival: Arrival) -> Vec<u64> {
    match arrival {
        Arrival::Deliver(frames) => frames.iter().map(|(_, p)| p.seq).collect(),
        other => panic!("nothing delivered: {other:?}"),
    }
}

#[test]
fn a_replay_position_past_a_gap_is_held_and_the_gap_fetched() {
    let mut delivered = GroupDelivered::default();
    assert_eq!(seqs(arrive(&mut delivered, 1)), vec![1]);
    assert!(matches!(
        arrive(&mut delivered, 4),
        Arrival::Fetch { after: 1, until: 3 }
    ));
    assert!(
        matches!(arrive(&mut delivered, 5), Arrival::Nothing),
        "one fetch per gap"
    );
    assert!(matches!(arrive(&mut delivered, 3), Arrival::Nothing));
    assert_eq!(seqs(arrive(&mut delivered, 2)), vec![2, 3, 4, 5]);
    assert!(matches!(arrive(&mut delivered, 4), Arrival::Nothing));
    assert_eq!(delivered.last(5, KEY), 5);
}

#[test]
fn a_fetch_that_brings_nothing_is_not_repeated() {
    let mut delivered = GroupDelivered::default();
    let _ = arrive(&mut delivered, 3);
    assert_eq!(delivered.fetched(5, KEY, false), None);
    assert!(
        matches!(arrive(&mut delivered, 4), Arrival::Fetch { after: 0, until: 2 }),
        "a later arrival asks again"
    );
    assert_eq!(delivered.fetched(5, KEY, true), Some((0, 2)));
}

#[test]
fn what_is_held_is_bounded_and_the_rest_fetched_in_its_turn() {
    let mut delivered = GroupDelivered::default();
    let past = 2 + MAX_HELD_POSITIONS as u64;
    for seq in 2..=past {
        let _ = arrive(&mut delivered, seq);
    }
    let freed = seqs(arrive(&mut delivered, 1));
    assert_eq!(freed.len(), MAX_HELD_POSITIONS + 1);
    assert_eq!(delivered.last(5, KEY), past - 1);
    assert!(matches!(
        arrive(&mut delivered, past + 1),
        Arrival::Fetch { after, until } if after == past - 1 && until == past
    ));
}

#[test]
fn the_position_that_starts_a_log_has_no_gap_before_it() {
    let mut delivered = GroupDelivered::default();
    let (position, frame) = at(40);
    let Arrival::Deliver(frames) = delivered.arrive(5, KEY, position, frame, true) else {
        panic!("the log's first position was held");
    };
    assert_eq!(frames.len(), 1);
}

#[test]
fn a_member_holding_through_a_position_is_not_given_it_again() {
    let mut delivered = GroupDelivered::default();
    let _ = arrive(&mut delivered, 3);
    let _ = arrive(&mut delivered, 7);
    let freed: Vec<u64> = delivered
        .holds_through(5, KEY, 2)
        .iter()
        .map(|(_, p)| p.seq)
        .collect();
    assert_eq!(freed, vec![3]);
    assert!(delivered.holds_through(5, KEY, 6).iter().map(|(_, p)| p.seq).eq([7]));
    assert!(matches!(arrive(&mut delivered, 7), Arrival::Nothing));
}
