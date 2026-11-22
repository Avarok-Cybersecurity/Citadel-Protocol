use crate::proto::packet_processor::includes::Instant;
use crate::proto::peer::mailbox::tests::{register, Manager};
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_io::tokio;
use citadel_types::proto::{MessageGroupKey, MessageGroupOptions};
use citadel_user::backend::BackendType;

struct Trio {
    manager: Manager,
    layer: CitadelNodePeerLayer<citadel_crypt::ratchets::stacked::StackedRatchet>,
    key: MessageGroupKey,
    creator: u64,
    members: [u64; 2],
    successor: u64,
}

/// A group created by `creator` with two members, both in; the creator has left, so the member
/// with the higher cid owns it.
async fn handed_on() -> Trio {
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    let creator = register(&manager, "creator").await;
    let (a, b) = (
        register(&manager, "member-a").await,
        register(&manager, "member-b").await,
    );
    let layer = CitadelNodePeerLayer::new(manager.get_persistence_handler().clone());
    layer.admit(creator, Instant::now());
    let _ = layer.register_peer(creator).await.unwrap();
    let key = layer
        .create_new_message_group(creator, &vec![a, b], MessageGroupOptions::default())
        .await
        .unwrap();
    assert!(layer.upgrade_peer_in_group(key, a).await);
    assert!(layer.upgrade_peer_in_group(key, b).await);
    let _ = layer.leave_group(key, creator).await;
    Trio {
        manager,
        layer,
        key,
        creator,
        members: [a, b],
        successor: a.max(b),
    }
}

/// A fresh layer over `manager`'s backend, as a restarted server builds.
async fn restart(
    manager: &Manager,
) -> CitadelNodePeerLayer<citadel_crypt::ratchets::stacked::StackedRatchet> {
    let restarted = CitadelNodePeerLayer::new(manager.get_persistence_handler().clone());
    assert!(restarted
        .restore_persisted_groups()
        .await
        .unwrap()
        .is_empty());
    restarted
}

#[tokio::test]
async fn the_recorded_owner_survives_a_restart() {
    let trio = handed_on().await;
    let restarted = restart(&trio.manager).await;
    assert_eq!(restarted.group_owner(trio.key).await, Some(trio.successor));
    assert_eq!(
        restarted.list_message_groups_for(trio.successor).await,
        vec![trio.key]
    );
}

#[tokio::test]
async fn a_group_outlives_its_creators_account_across_a_restart() {
    let trio = handed_on().await;
    drop(trio.layer);
    trio.manager
        .delete_client_by_cid(trio.creator)
        .await
        .unwrap();
    let restarted = restart(&trio.manager).await;
    assert_eq!(
        restarted.group_owner(trio.key).await,
        Some(trio.successor),
        "a group whose creator's account is gone did not survive the restart"
    );
}

#[tokio::test]
async fn a_closed_group_stays_closed_across_a_restart() {
    let trio = handed_on().await;
    for member in trio.members {
        let _ = trio.layer.leave_group(trio.key, member).await;
    }
    assert!(!trio.layer.message_group_exists(trio.key).await);
    let restarted = restart(&trio.manager).await;
    assert!(!restarted.message_group_exists(trio.key).await);
}

#[tokio::test]
async fn a_groups_row_moves_with_its_ownership() {
    use crate::proto::peer::group_persistence::GROUPS;
    let trio = handed_on().await;
    let pers = trio.manager.get_persistence_handler();
    let under = |cid| async move {
        pers.get_byte_map_values_by_key(cid, 0, GROUPS)
            .await
            .unwrap()
            .len()
    };
    assert_eq!(
        under(trio.creator).await,
        0,
        "the creator still holds the row"
    );
    assert_eq!(
        under(trio.successor).await,
        1,
        "the owner does not hold the row"
    );
}

#[tokio::test]
async fn a_row_of_an_earlier_release_is_read_as_its_group() {
    use crate::proto::peer::group_persistence::{PersistedGroup, GROUPS};
    use citadel_user::serialization::SyncIO;
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    let creator = register(&manager, "creator").await;
    let mgid = 7u128;
    let row = PersistedGroup {
        owner: creator,
        options: MessageGroupOptions::default(),
        members: vec![creator],
        pending: vec![],
        tree: 0,
    };
    let _ = manager
        .get_persistence_handler()
        .store_byte_map_value(
            creator,
            0,
            GROUPS,
            &format!("{mgid:032x}"),
            row.serialize_to_vector().unwrap(),
        )
        .await
        .unwrap();
    let restarted = restart(&manager).await;
    let key = MessageGroupKey { cid: creator, mgid };
    assert_eq!(restarted.group_owner(key).await, Some(creator));
}
