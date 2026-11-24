use super::*;
use crate::proto::peer::group_position::tests::{group_with, position, Group};
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_io::tokio;
use citadel_types::proto::{GroupMessageId, MessageGroupOptions};
use std::time::Duration;

fn limits(max_messages: u32) -> GroupLogLimits {
    GroupLogLimits {
        max_age: Duration::from_secs(3600),
        max_messages,
        max_bytes: 1 << 24,
        max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES,
    }
}

async fn replay_group(max_messages: u32) -> Group {
    group_with(MessageGroupOptions {
        replay: Some(limits(max_messages)),
        ..Default::default()
    })
    .await
}

async fn send(g: &Group, book: &mut GroupOrderBook) -> GroupPosition {
    match position(&g.layer, book, g.key, g.member, GroupMessageId::random()).await {
        Positioned::New { position, .. } => position,
        Positioned::Retry { .. } => panic!("a fresh id was a retry"),
    }
}

fn frames_of(read: LogRead) -> Vec<u64> {
    match read {
        LogRead::Frames { frames, .. } => frames
            .iter()
            .map(|frame| match frame {
                GroupBroadcast::Ordered { position, .. } => position.seq,
                other => panic!("not positioned: {other:?}"),
            })
            .collect(),
        LogRead::Trimmed { earliest, .. } => panic!("trimmed to {earliest}"),
        LogRead::NoReplay => panic!("no log"),
    }
}

#[tokio::test]
async fn a_group_created_with_replay_is_logged_from_one_and_read_back_in_order() {
    let g = replay_group(100).await;
    let mut book = GroupOrderBook::default();
    let first = send(&g, &mut book).await;
    assert_eq!(first.seq, 1);
    assert!(
        first.chain.is_some(),
        "a replay position carries its chain head"
    );
    let _ = send(&g, &mut book).await;
    let read = g.layer.read_group_log(&mut book, g.key, 0, u64::MAX).await;
    assert_eq!(frames_of(read.unwrap()), vec![1, 2]);
    let after = g.layer.read_group_log(&mut book, g.key, 1, 1).await;
    assert_eq!(frames_of(after.unwrap()), Vec::<u64>::new());
}

#[tokio::test]
async fn replay_turned_on_later_starts_at_the_next_position_with_the_event() {
    let g = group_with(MessageGroupOptions::default()).await;
    let mut book = GroupOrderBook::default();
    let before = send(&g, &mut book).await;
    assert!(before.chain.is_none());
    let server = Some(limits(1000));
    let refused = g
        .layer
        .enable_group_replay(&mut book, g.key, g.member, limits(10), server, 0)
        .await;
    assert_eq!(
        refused.unwrap().err(),
        Some(GroupReplayRefusal::NotTheOwner)
    );
    let (frame, at) = g
        .layer
        .enable_group_replay(&mut book, g.key, g.creator, limits(10), server, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(at.seq, before.seq + 1);
    assert!(matches!(
        frame,
        GroupBroadcast::Ordered { frame, .. }
            if matches!(*frame, GroupBroadcast::ReplayEnabled { order, .. } if order.since == at.seq)
    ));
    let next = send(&g, &mut book).await;
    assert_eq!((next.seq, next.chain.is_some()), (at.seq + 1, true));
    let again = g
        .layer
        .enable_group_replay(&mut book, g.key, g.creator, limits(10), server, 0)
        .await;
    assert_eq!(
        again.unwrap().err(),
        Some(GroupReplayRefusal::NotApplicable)
    );
    let read = g.layer.read_group_log(&mut book, g.key, 0, u64::MAX).await;
    assert_eq!(frames_of(read.unwrap()), vec![at.seq, next.seq]);
}

#[tokio::test]
async fn replay_turned_on_later_numbers_without_gaps_across_a_restart() {
    let g = group_with(MessageGroupOptions::default()).await;
    let mut book = GroupOrderBook::default();
    let _ = send(&g, &mut book).await;
    let (_, at) = g
        .layer
        .enable_group_replay(
            &mut book,
            g.key,
            g.creator,
            limits(10),
            Some(limits(1000)),
            0,
        )
        .await
        .unwrap()
        .unwrap();
    let restarted = CitadelNodePeerLayer::new(g.manager.get_persistence_handler().clone());
    let _ = restarted.restore_persisted_groups().await.unwrap();
    let mut book = GroupOrderBook::default();
    let next = match position(
        &restarted,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await
    {
        Positioned::New { position, .. } => position.seq,
        Positioned::Retry { .. } => panic!("a fresh id was a retry"),
    };
    assert_eq!(next, at.seq + 1, "a gap after replay started at {}", at.seq);
}

#[test]
fn a_server_keeping_no_log_or_limits_too_small_are_refused() {
    assert_eq!(admitted(limits(10), None), Err(GroupReplayRefusal::NotKept));
    let small = GroupLogLimits {
        max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES - 1,
        ..limits(10)
    };
    assert_eq!(
        admitted(limits(10), Some(small)),
        Err(GroupReplayRefusal::TooSmall),
        "a server whose own cap cannot carry the body"
    );
    assert_eq!(admitted(limits(10), Some(limits(4))), Ok(limits(4)));
    let ephemeral = MessageGroupOptions {
        ephemeral: true,
        ..Default::default()
    };
    assert_eq!(
        admitted_at_creation(&ephemeral, limits(10), Some(limits(10))),
        Err(GroupReplayRefusal::NotApplicable)
    );
}

#[tokio::test]
async fn a_fetch_of_what_the_log_no_longer_keeps_is_named_trimmed() {
    let g = replay_group(2).await;
    let mut book = GroupOrderBook::default();
    for _ in 0..4 {
        let _ = send(&g, &mut book).await;
    }
    let read = g.layer.read_group_log(&mut book, g.key, 0, u64::MAX).await;
    assert!(matches!(
        read.unwrap(),
        LogRead::Trimmed { earliest: 3, .. }
    ));
    let tail = g.layer.read_group_log(&mut book, g.key, 2, u64::MAX).await;
    assert_eq!(frames_of(tail.unwrap()), vec![3, 4]);
}

#[tokio::test]
async fn a_message_larger_than_the_log_takes_is_refused() {
    let g = replay_group(10).await;
    let mut book = GroupOrderBook::default();
    let cap = GroupLogLimits::MIN_MESSAGE_BYTES as usize;
    let fits = g.layer.group_log_refuses(&mut book, g.key, cap).await;
    assert_eq!(fits.unwrap(), None);
    let over = g.layer.group_log_refuses(&mut book, g.key, cap + 1).await;
    assert!(matches!(
        over.unwrap(),
        Some(GroupMessageRefusal::TooLarge { max_bytes, .. }) if max_bytes as usize == cap
    ));
}

#[tokio::test]
async fn a_replay_groups_log_moves_with_its_owner_and_survives_the_creators_account() {
    let g = replay_group(100).await;
    let mut book = GroupOrderBook::default();
    let first = send(&g, &mut book).await;
    let _ = g.layer.leave_group(g.key, g.creator).await;
    let second = send(&g, &mut book).await;
    assert_eq!(second.seq, first.seq + 1);
    g.manager.delete_client_by_cid(g.creator).await.unwrap();
    let restarted = CitadelNodePeerLayer::new(g.manager.get_persistence_handler().clone());
    let _ = restarted.restore_persisted_groups().await.unwrap();
    let mut book = GroupOrderBook::default();
    let read = restarted
        .read_group_log(&mut book, g.key, 0, u64::MAX)
        .await;
    assert_eq!(frames_of(read.unwrap()), vec![first.seq, second.seq]);
    let next = match position(
        &restarted,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await
    {
        Positioned::New { position, .. } => position,
        Positioned::Retry { .. } => panic!("a fresh id was a retry"),
    };
    assert_eq!(next.seq, second.seq + 1, "no gap after the restart");
}
