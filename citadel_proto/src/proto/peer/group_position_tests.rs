use super::*;
use crate::proto::packet_processor::includes::Instant;
use crate::proto::peer::mailbox::tests::{register, Manager};
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_types::proto::{GroupMessageId, MessageGroupOptions};
use citadel_user::backend::BackendType;

pub(crate) type Layer = CitadelNodePeerLayer<StackedRatchet>;

pub(crate) struct Group {
    pub manager: Manager,
    pub layer: Layer,
    pub key: MessageGroupKey,
    pub creator: u64,
    pub member: u64,
}

async fn group() -> Group {
    group_with(MessageGroupOptions::default()).await
}

/// A group of a creator and one member, created with `options`.
pub(crate) async fn group_with(options: MessageGroupOptions) -> Group {
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    let creator = register(&manager, "creator").await;
    let member = register(&manager, "member").await;
    let layer = CitadelNodePeerLayer::new(manager.get_persistence_handler().clone());
    layer.admit(creator, Instant::now());
    let _ = layer.register_peer(creator).await.unwrap();
    let key = layer
        .create_new_message_group(creator, &vec![member], options)
        .await
        .unwrap();
    assert!(layer.upgrade_peer_in_group(key, member).await);
    Group {
        manager,
        layer,
        key,
        creator,
        member,
    }
}

pub(crate) fn message(key: MessageGroupKey, sender: u64, id: GroupMessageId) -> GroupBroadcast {
    GroupBroadcast::Message {
        sender,
        key,
        id,
        message: SecBuffer::from(vec![1u8; 4]),
    }
}

/// Positions a message from `sender` under `id` on `layer`, with a fresh book standing for
/// whatever `book` holds.
pub(crate) async fn position(
    layer: &Layer,
    book: &mut GroupOrderBook,
    key: MessageGroupKey,
    sender: u64,
    id: GroupMessageId,
) -> Positioned {
    layer
        .position_group_broadcast(book, key, message(key, sender, id), 0)
        .await
        .unwrap()
}

pub(crate) fn seq(positioned: &Positioned) -> u64 {
    match positioned {
        Positioned::New { position, .. } | Positioned::Retry { position } => position.seq,
    }
}

#[tokio::test]
async fn a_message_is_positioned_inside_an_ordered_frame() {
    let g = group().await;
    let mut book = GroupOrderBook::default();
    let id = GroupMessageId::random();
    let Positioned::New { frame, position } =
        position(&g.layer, &mut book, g.key, g.member, id).await
    else {
        panic!("a fresh id is a new position");
    };
    assert_eq!(position.seq, 1);
    assert!(matches!(
        frame,
        GroupBroadcast::Ordered { key, position: p, frame } if key == g.key && p == position
            && matches!(*frame, GroupBroadcast::Message { id: inner, .. } if inner == id)
    ));
}

#[tokio::test]
async fn a_message_sent_again_under_its_id_keeps_its_position() {
    let g = group().await;
    let mut book = GroupOrderBook::default();
    let id = GroupMessageId::random();
    let first = position(&g.layer, &mut book, g.key, g.member, id).await;
    let _ = position(
        &g.layer,
        &mut book,
        g.key,
        g.creator,
        GroupMessageId::random(),
    )
    .await;
    let again = position(&g.layer, &mut book, g.key, g.member, id).await;
    assert!(matches!(again, Positioned::Retry { .. }));
    assert_eq!(seq(&again), seq(&first));
}

#[tokio::test]
async fn positions_never_repeat_after_a_restart() {
    let g = group().await;
    let mut book = GroupOrderBook::default();
    let mut last = 0;
    for _ in 0..3 {
        last = seq(&position(
            &g.layer,
            &mut book,
            g.key,
            g.member,
            GroupMessageId::random(),
        )
        .await);
    }
    // A restarted server's book is empty, and reads the order back from the store.
    let restarted = CitadelNodePeerLayer::new(g.manager.get_persistence_handler().clone());
    let _ = restarted.restore_persisted_groups().await.unwrap();
    let mut book = GroupOrderBook::default();
    let next = seq(&position(
        &restarted,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await);
    assert!(next > last, "{next} repeats or goes back from {last}");
}

#[tokio::test]
async fn positions_never_repeat_after_the_owner_changes_and_the_creators_account_goes() {
    let g = group().await;
    let mut book = GroupOrderBook::default();
    let _ = position(
        &g.layer,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await;
    // The creator leaves; the member owns the group, and its order is written under it.
    let _ = g.layer.leave_group(g.key, g.creator).await;
    let last = seq(&position(
        &g.layer,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await);
    // The creator's account, and whatever was stored under it, is gone.
    g.manager.delete_client_by_cid(g.creator).await.unwrap();
    let restarted = CitadelNodePeerLayer::new(g.manager.get_persistence_handler().clone());
    let _ = restarted.restore_persisted_groups().await.unwrap();
    let mut book = GroupOrderBook::default();
    let next = seq(&position(
        &restarted,
        &mut book,
        g.key,
        g.member,
        GroupMessageId::random(),
    )
    .await);
    assert!(next > last, "{next} repeats or goes back from {last}");
}
