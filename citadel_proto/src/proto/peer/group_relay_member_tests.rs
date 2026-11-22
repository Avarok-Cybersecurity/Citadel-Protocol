//! The server relays a group message only from a member of the group.

use super::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;

const OWNER: u64 = 10;
const MEMBER: u64 = 20;
const OUTSIDER: u64 = 30;

async fn layer_with_group() -> (CitadelNodePeerLayer<StackedRatchet>, MessageGroupKey) {
    let acc = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let layer = CitadelNodePeerLayer::new(acc.get_persistence_handler().clone());
    for cid in [OWNER, MEMBER, OUTSIDER] {
        let _ = layer.register_peer(cid).await.unwrap();
    }
    let key = layer
        .create_new_message_group(OWNER, &vec![MEMBER], MessageGroupOptions::default())
        .await
        .expect("the group is created");
    assert!(layer.upgrade_peer_in_group(key, MEMBER).await);
    (layer, key)
}

#[tokio::test]
async fn a_member_may_send_to_its_group() {
    let (layer, key) = layer_with_group().await;
    for sender in [OWNER, MEMBER] {
        let admitted = layer
            .admit_group_message(key, sender, 8, Instant::now())
            .await;
        assert!(admitted.is_ok(), "{sender} refused: {admitted:?}");
    }
}

#[tokio::test]
async fn a_non_member_may_not_send_to_a_group() {
    let (layer, key) = layer_with_group().await;
    let admitted = layer
        .admit_group_message(key, OUTSIDER, 8, Instant::now())
        .await;
    assert!(
        admitted.is_err(),
        "a cid outside the group was admitted: {admitted:?}"
    );
}
