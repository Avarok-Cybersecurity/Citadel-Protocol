//! What the peer layer holds for a session is bounded and ends with it. Two deregistrations of
//! the same pair that cross are answered as one; a deregistration's posting matches once and
//! lives only for its window, so it never stands in for a later deregistration of a pair
//! registered again since. A session's crossed-dial ticket mappings are capped and dropped at
//! its shutdown. Time is tokio's paused clock, which the posting's delay queue reads.

use super::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;

const ALICE: u64 = 10;
const BOB: u64 = 20;

async fn layer() -> CitadelNodePeerLayer<StackedRatchet> {
    let acc = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let layer = CitadelNodePeerLayer::new(acc.get_persistence_handler().clone());
    for cid in [ALICE, BOB] {
        let _ = layer.register_peer(cid).await.unwrap();
    }
    layer
}

/// Alice's deregistration of Bob, as the server posts it once it has removed the pair.
async fn alice_deregisters_bob(layer: &CitadelNodePeerLayer<StackedRatchet>, ticket: Ticket) {
    layer
        .inner
        .write()
        .await
        .post_deregistration(
            ALICE,
            ticket,
            PeerConnectionType::LocalGroupPeer {
                session_cid: ALICE,
                peer_cid: BOB,
            },
        )
        .await;
}

async fn bob_crosses(layer: &CitadelNodePeerLayer<StackedRatchet>) -> Option<Ticket> {
    layer
        .inner
        .write()
        .await
        .take_simultaneous_deregister(BOB, ALICE)
}

#[tokio::test(start_paused = true)]
async fn a_crossing_deregistration_matches_its_posting_once() {
    let layer = layer().await;
    alice_deregisters_bob(&layer, Ticket(1)).await;
    assert_eq!(bob_crosses(&layer).await, Some(Ticket(1)));
    assert_eq!(bob_crosses(&layer).await, None, "the posting matched twice");
}

#[tokio::test(start_paused = true)]
async fn a_deregistration_posting_lapses_after_its_window() {
    let layer = layer().await;
    alice_deregisters_bob(&layer, Ticket(1)).await;
    let executor = layer.create_executor().await;
    tokio::select! {
        ended = executor => panic!("the peer layer's executor ended: {ended:?}"),
        _ = tokio::time::sleep(SIMULTANEOUS_DEREGISTER_WINDOW + Duration::from_secs(1)) => {}
    }
    assert_eq!(bob_crosses(&layer).await, None);
}

#[tokio::test]
async fn a_sessions_crossed_dial_mappings_are_bounded_and_end_with_it() {
    let layer = layer().await;
    let at = Instant::now();
    layer.admit(ALICE, at);
    {
        let mut inner = layer.inner.write().await;
        for n in 0..1_000u128 {
            inner.insert_mapped_ticket(ALICE, Ticket(n), Ticket(n + 1_000_000));
        }
        assert_eq!(
            inner.simultaneous_ticket_mappings[&ALICE].len(),
            MAX_CROSSED_TICKET_MAPPINGS_PER_SESSION
        );
        // The newest are kept, and each is taken once.
        assert_eq!(
            inner.take_mapped_ticket(ALICE, Ticket(999)),
            Some(Ticket(1_000_999))
        );
        assert_eq!(inner.take_mapped_ticket(ALICE, Ticket(999)), None);
        assert_eq!(inner.take_mapped_ticket(ALICE, Ticket(0)), None);
    }
    layer.on_session_shutdown(ALICE, at).await.unwrap();
    assert!(!layer
        .inner
        .read()
        .await
        .simultaneous_ticket_mappings
        .contains_key(&ALICE));
}

#[tokio::test]
async fn a_session_cannot_have_more_requests_pending_than_the_cap() {
    let layer = layer().await;
    let inner = layer.inner.write().await;
    let mut admitted = 0;
    for n in 0..1_000u128 {
        if inner.admit_posting(ALICE).is_ok() {
            inner
                .post_deregistration(
                    ALICE,
                    Ticket(n),
                    PeerConnectionType::LocalGroupPeer {
                        session_cid: ALICE,
                        peer_cid: BOB,
                    },
                )
                .await;
            admitted += 1;
        }
    }
    assert_eq!(admitted, MAX_PENDING_POSTINGS_PER_SESSION);
    // The cap is per session.
    assert!(inner.admit_posting(BOB).is_ok());
}
