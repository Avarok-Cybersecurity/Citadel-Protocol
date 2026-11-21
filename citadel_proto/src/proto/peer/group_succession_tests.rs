use super::*;
use crate::proto::packet_processor::includes::Instant;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::proto::{MessageGroupOptions, ReadPolicy};
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::{BackendType, PersistenceHandler};

const OWNER: u64 = 10;
const LOW: u64 = 20;
const HIGH: u64 = 30;

#[test]
fn the_successor_is_the_member_with_the_highest_cid() {
    assert_eq!(successor(&[LOW, HIGH]), Some(HIGH));
    assert_eq!(successor(&[HIGH, LOW]), Some(HIGH));
    assert_eq!(successor(&[]), None);
}

#[test]
fn only_the_owner_leaving_passes_a_flat_group_on() {
    assert_eq!(
        after_leave(OWNER, OWNER, &[LOW, HIGH], true),
        Succession::PassesTo(HIGH)
    );
    assert_eq!(
        after_leave(OWNER, LOW, &[OWNER, HIGH], true),
        Succession::Stays
    );
    assert_eq!(after_leave(OWNER, OWNER, &[], true), Succession::Ends);
    assert_eq!(after_leave(OWNER, LOW, &[], true), Succession::Ends);
}

#[test]
fn a_command_hierarchys_owner_leaving_ends_it() {
    assert_eq!(
        after_leave(OWNER, OWNER, &[LOW, HIGH], false),
        Succession::Ends
    );
    assert_eq!(after_leave(OWNER, LOW, &[OWNER], false), Succession::Stays);
}

async fn backend() -> PersistenceHandler<StackedRatchet, StackedRatchet> {
    AccountManager::<StackedRatchet, StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap()
        .get_persistence_handler()
        .clone()
}

async fn group_of(
    pers: &PersistenceHandler<StackedRatchet, StackedRatchet>,
    options: MessageGroupOptions,
) -> (CitadelNodePeerLayer<StackedRatchet>, MessageGroupKey) {
    let layer = CitadelNodePeerLayer::new(pers.clone());
    layer.admit(OWNER, Instant::now());
    let _ = layer.register_peer(OWNER).await.unwrap();
    let key = layer
        .create_new_message_group(OWNER, &vec![LOW, HIGH], options)
        .await
        .unwrap();
    assert!(layer.upgrade_peer_in_group(key, LOW).await);
    assert!(layer.upgrade_peer_in_group(key, HIGH).await);
    (layer, key)
}

#[tokio::test]
async fn the_owner_leaving_records_the_highest_cid_member_as_owner() {
    let (layer, key) = group_of(&backend().await, MessageGroupOptions::default()).await;
    assert_eq!(
        layer.leave_group(key, OWNER).await,
        Leave::Transferred {
            owner: HIGH,
            previous: OWNER,
            tree: 0,
            remaining: vec![LOW, HIGH],
        }
    );
    assert_eq!(layer.group_owner(key).await, Some(HIGH));
    assert_eq!(layer.list_message_groups_for(HIGH).await, vec![key]);
    assert!(layer.list_message_groups_for(OWNER).await.is_empty());
    assert_eq!(layer.list_message_groups_with_member(LOW).await, vec![key]);
    assert!(layer.list_message_groups_with_member(HIGH).await.is_empty());
}

#[tokio::test]
async fn a_replayed_leave_changes_nothing_and_successive_leaves_converge() {
    let (layer, key) = group_of(&backend().await, MessageGroupOptions::default()).await;
    let _ = layer.leave_group(key, OWNER).await;
    assert_eq!(layer.leave_group(key, OWNER).await, Leave::NotAMember);
    assert_eq!(layer.group_owner(key).await, Some(HIGH));
    assert!(matches!(
        layer.leave_group(key, HIGH).await,
        Leave::Transferred {
            owner: LOW,
            previous: HIGH,
            ..
        }
    ));
    assert_eq!(
        layer.leave_group(key, LOW).await,
        Leave::Closed { remaining: vec![] }
    );
    assert!(!layer.message_group_exists(key).await);
}

#[tokio::test]
async fn a_member_leaving_keeps_the_owner() {
    let (layer, key) = group_of(&backend().await, MessageGroupOptions::default()).await;
    assert_eq!(
        layer.leave_group(key, HIGH).await,
        Leave::Left {
            remaining: vec![OWNER, LOW]
        }
    );
    assert_eq!(layer.group_owner(key).await, Some(OWNER));
}

#[tokio::test]
async fn a_hierarchys_owner_leaving_closes_it_for_its_members() {
    let options = MessageGroupOptions {
        hierarchy: GroupHierarchyMode::CommandHierarchy {
            read_policy: ReadPolicy::SuperiorOnly,
            ranks: Default::default(),
        },
        ..Default::default()
    };
    let (layer, key) = group_of(&backend().await, options).await;
    assert_eq!(
        layer.leave_group(key, OWNER).await,
        Leave::Closed {
            remaining: vec![LOW, HIGH]
        }
    );
    assert!(!layer.message_group_exists(key).await);
}

#[tokio::test]
async fn the_recorded_owner_survives_a_restart() {
    use crate::proto::peer::mailbox::tests::{register, Manager};
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    // The registry is kept under its creator's account.
    let creator = register(&manager, "creator").await;
    let pers = manager.get_persistence_handler().clone();
    let layer = CitadelNodePeerLayer::new(pers.clone());
    layer.admit(creator, Instant::now());
    let _ = layer.register_peer(creator).await.unwrap();
    let key = layer
        .create_new_message_group(creator, &vec![LOW, HIGH], MessageGroupOptions::default())
        .await
        .unwrap();
    assert!(layer.upgrade_peer_in_group(key, LOW).await);
    assert!(layer.upgrade_peer_in_group(key, HIGH).await);
    let _ = layer.leave_group(key, creator).await;

    // A fresh layer over the same backend, as a restarted server builds.
    let restarted = CitadelNodePeerLayer::new(pers);
    assert!(restarted
        .restore_persisted_groups()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(restarted.group_owner(key).await, Some(HIGH));
    assert_eq!(restarted.list_message_groups_for(HIGH).await, vec![key]);
}

#[tokio::test]
async fn a_deregistered_owner_leaves_every_group_it_is_in() {
    let (layer, key) = group_of(&backend().await, MessageGroupOptions::default()).await;
    let left = layer.leave_all_groups(OWNER).await;
    assert!(matches!(
        left.as_slice(),
        [(left_key, Leave::Transferred { owner: HIGH, .. })] if *left_key == key
    ));
    assert!(layer.leave_all_groups(OWNER).await.is_empty());
}
