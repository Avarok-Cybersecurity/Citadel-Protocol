//! A CID is permanent, so a session that replaces another (a reconnect whose resume token
//! retires the server's stale copy) registers the same cid while the replaced session's own
//! shutdown is still to run. Seen on CI (citadel-agent run 37260430125): that shutdown removed
//! the new session's postings, and every PeerConnect it then made was refused.

use super::*;
use crate::proto::packet_processor::includes::Instant;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;
use std::time::Duration;

const CID: u64 = 10;

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

async fn has_postings(layer: &CitadelNodePeerLayer<StackedRatchet>, cid: u64) -> bool {
    let this = layer.inner.read().await;
    let shared = this.inner.read();
    shared.observed_postings.contains_key(&cid)
}

#[tokio::test]
async fn a_replaced_sessions_late_shutdown_keeps_its_replacements_postings() {
    let layer = layer().await;
    let replaced = Instant::now();
    let replacement = replaced + Duration::from_millis(1);
    let _ = layer.register_peer(CID, replaced).await.unwrap();
    let _ = layer.register_peer(CID, replacement).await.unwrap();

    layer.on_session_shutdown(CID, replaced).await.unwrap();
    assert!(
        has_postings(&layer, CID).await,
        "the replaced session's shutdown took the new session's postings"
    );

    layer.on_session_shutdown(CID, replacement).await.unwrap();
    assert!(
        !has_postings(&layer, CID).await,
        "its own shutdown releases them"
    );
}

#[tokio::test]
async fn a_session_that_ends_before_its_replacement_registers_releases_its_own() {
    let layer = layer().await;
    let replaced = Instant::now();
    let _ = layer.register_peer(CID, replaced).await.unwrap();
    layer.on_session_shutdown(CID, replaced).await.unwrap();
    assert!(!has_postings(&layer, CID).await);
    let _ = layer
        .register_peer(CID, replaced + Duration::from_millis(1))
        .await
        .unwrap();
    assert!(
        has_postings(&layer, CID).await,
        "the replacement starts afresh"
    );
}
