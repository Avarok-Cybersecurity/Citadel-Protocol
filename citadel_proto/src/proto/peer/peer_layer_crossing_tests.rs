//! Which pending dials a new dial may be merged with. Deterministic: no timing.

use super::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;

const POSTING_TTL: Duration = Duration::from_secs(65);
const A: u64 = 111;
const B: u64 = 222;

async fn peer_layer() -> CitadelNodePeerLayer<StackedRatchet> {
    let accounts = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let layer = CitadelNodePeerLayer::new(accounts.get_persistence_handler().clone());
    for cid in [A, B] {
        let _ = layer.register_peer(cid).await.unwrap();
    }
    layer
}

fn dial(from: u64, to: u64, ticket: Ticket) -> PeerSignal {
    PeerSignal::PostConnect {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: from,
            peer_cid: to,
        },
        ticket_opt: Some(ticket),
        invitee_response: None,
        session_security_settings: crate::prelude::SessionSecuritySettingsBuilder::default()
            .build()
            .unwrap(),
        udp_mode: Default::default(),
        session_password: None,
    }
}

async fn post(
    inner: &CitadelNodePeerLayerInner<StackedRatchet>,
    from: u64,
    to: u64,
    ticket: Ticket,
    crossing: Crossing,
) {
    inner
        .insert_tracked_posting(
            from,
            POSTING_TTL,
            ticket,
            dial(from, to, ticket),
            crossing,
            |_| {},
        )
        .await;
}

/// The pair's link is established (b accepts a's dial), then b dials a duplicate over that live
/// link. After the link ends, a's next dial must not be merged with that duplicate: b is not
/// dialling any more, and the server would answer a with an accept b never gave.
#[citadel_io::tokio::test]
async fn a_dial_made_over_a_live_link_is_not_merged_with_a_later_one() {
    let layer = peer_layer().await;
    let mut inner = layer.inner.write().await;
    post(&inner, A, B, Ticket(1), Crossing::Open).await;
    assert!(inner
        .remove_answered_posting(A, Ticket(1), B, Answer::Accepts)
        .is_some());

    post(&inner, B, A, Ticket(2), Crossing::OverLiveLink).await;

    assert_eq!(inner.check_simultaneous_connect(A, B), None);
}

/// R-DIAL's crossed-dial merge is untouched: a dial made with no live link is still matched.
#[citadel_io::tokio::test]
async fn a_dial_made_with_no_live_link_is_still_merged() {
    let layer = peer_layer().await;
    let mut inner = layer.inner.write().await;
    post(&inner, B, A, Ticket(2), Crossing::Open).await;

    assert_eq!(inner.check_simultaneous_connect(A, B), Some(Ticket(2)));
}

/// A refusal consumes the dial it answers and nothing else: the refuser's own dial to the
/// dialler stays pending, so the dialler's answer to it still finds it.
#[citadel_io::tokio::test]
async fn a_refusal_leaves_the_other_dial_of_the_pair_pending() {
    let layer = peer_layer().await;
    let mut inner = layer.inner.write().await;
    post(&inner, A, B, Ticket(1), Crossing::OverLiveLink).await;
    post(&inner, B, A, Ticket(2), Crossing::OverLiveLink).await;

    assert!(inner
        .remove_answered_posting(A, Ticket(1), B, Answer::Refuses)
        .is_some());

    assert!(inner
        .remove_answered_posting(B, Ticket(2), A, Answer::Refuses)
        .is_some());
}

/// An accept still settles the pair: every other pending dial between the two goes with it.
#[citadel_io::tokio::test]
async fn an_accept_supersedes_the_pairs_other_dials() {
    let layer = peer_layer().await;
    let mut inner = layer.inner.write().await;
    post(&inner, A, B, Ticket(1), Crossing::Open).await;
    post(&inner, B, A, Ticket(2), Crossing::Open).await;

    assert!(inner
        .remove_answered_posting(A, Ticket(1), B, Answer::Accepts)
        .is_some());

    assert_eq!(inner.check_simultaneous_connect(A, B), None);
    assert!(inner
        .remove_answered_posting(B, Ticket(2), A, Answer::Refuses)
        .is_none());
}
