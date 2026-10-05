//! A CID is permanent, so a session that replaces another (a reconnect whose resume token
//! retires the server's stale copy) is admitted under the same cid while the replaced session's
//! own shutdown is still to run. Seen on CI (citadel-agent run 37260430125): that shutdown
//! removed the new session's postings, and every PeerConnect it then made was refused. The
//! same shutdown also drops the cid's group watches and settles its groups' departure; each
//! step acts only while its session is the cid's current one (`admit`).

use super::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupOptions, ReadPolicy};
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;
use std::time::Duration;

const CID: u64 = 10;
const MEMBER: u64 = 20;

async fn layer() -> CitadelNodePeerLayer<StackedRatchet> {
    let acc = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    CitadelNodePeerLayer::new(acc.get_persistence_handler().clone())
}

/// `CID`'s session `at` admitted and registered, as a connect does.
async fn connect(layer: &CitadelNodePeerLayer<StackedRatchet>, at: Instant) {
    layer.admit(CID, at);
    let _ = layer.register_peer(CID).await.unwrap();
}

async fn has_postings(layer: &CitadelNodePeerLayer<StackedRatchet>) -> bool {
    let this = layer.inner.read().await;
    let shared = this.inner.read();
    shared.observed_postings.contains_key(&CID)
}

fn hierarchical() -> MessageGroupOptions {
    MessageGroupOptions {
        hierarchy: GroupHierarchyMode::CommandHierarchy {
            read_policy: ReadPolicy::SuperiorOnly,
            ranks: Default::default(),
        },
        ..Default::default()
    }
}

/// The shutdown task's steps, in its order, for the session `incarnation`.
async fn shut_down(
    layer: &CitadelNodePeerLayer<StackedRatchet>,
    incarnation: Instant,
) -> crate::proto::peer::group_retention::OwnerDeparture {
    layer.on_session_shutdown(CID, incarnation).await.unwrap();
    layer.drop_group_watches(CID, incarnation).await;
    let departure = layer.on_owner_departure(CID, incarnation, 0).await;
    layer.retire(CID, incarnation);
    departure
}

#[tokio::test]
async fn a_replaced_sessions_late_shutdown_leaves_its_replacement_alone() {
    let layer = layer().await;
    let replaced = Instant::now();
    let replacement = replaced + Duration::from_millis(1);
    connect(&layer, replaced).await;
    connect(&layer, replacement).await;
    let group = layer
        .create_new_message_group(CID, &vec![MEMBER], hierarchical())
        .await
        .unwrap();
    let watched = MessageGroupKey {
        cid: MEMBER,
        mgid: 7,
    };
    let _ = layer.watch_group(CID, Ticket(1), watched).await;

    let departure = shut_down(&layer, replaced).await;

    assert!(
        has_postings(&layer).await,
        "the replaced session's shutdown took the new session's postings"
    );
    assert!(
        layer.message_group_exists(group).await && departure.dissolved.is_empty(),
        "the replaced session's departure dissolved the new session's group: {departure:?}"
    );
    assert_eq!(
        layer.take_group_watchers(watched).await,
        vec![(CID, Ticket(1))],
        "the replaced session's shutdown dropped the new session's watch"
    );

    let own = shut_down(&layer, replacement).await;
    assert!(
        !has_postings(&layer).await,
        "its own shutdown releases them"
    );
    assert_eq!(
        own.dissolved.len(),
        1,
        "and its own departure dissolves its group"
    );
}

#[tokio::test]
async fn a_session_that_ends_before_its_replacement_is_admitted_releases_its_own() {
    let layer = layer().await;
    let replaced = Instant::now();
    connect(&layer, replaced).await;
    let group = layer
        .create_new_message_group(CID, &vec![MEMBER], hierarchical())
        .await
        .unwrap();
    let departure = shut_down(&layer, replaced).await;
    assert!(!has_postings(&layer).await);
    assert_eq!(departure.dissolved.len(), 1);
    assert!(!layer.message_group_exists(group).await);

    connect(&layer, replaced + Duration::from_millis(1)).await;
    assert!(has_postings(&layer).await, "the replacement starts afresh");
}
