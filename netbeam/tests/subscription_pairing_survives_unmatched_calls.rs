//! A call that only one side makes must not change what the next calls pair with.
//!
//! The P2P campaign runs every stage under a timeout over one long-lived endpoint, and each side
//! decides alone whether a stage got far enough for its readiness `sync()`. So one side regularly
//! makes a call the other never matches, either cut off by its timeout or still waiting while the
//! peer moves on to the next stage. On a wire that pairs subscriptions by how many each side has
//! opened, that one call shifts every later direct, TURN and re-arm attempt on the endpoint.

mod common;

use citadel_io::tokio;
use futures::FutureExt;
use netbeam::multiplex::OwnedMultiplexedSubscription;
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::network_application::NetworkApplication;
use netbeam::sync::subscription::{Subscribable, SubscriptionBiStream};
use netbeam::sync::wire::{Topic, WireRevision};
use netbeam::sync::RelativeNodeType;
use rstest::rstest;
use std::time::Duration;

const WIRE: WireRevision = WireRevision::Exchanged;
const DIRECT_READY: Topic = Topic::new(1);
const TURN: Topic = Topic::new(2);
/// A hang guard: everything here is in-memory and completes in microseconds or never.
const HANG_GUARD: Duration = Duration::from_secs(30);

fn side<'a>(
    node: RelativeNodeType,
    receiver: &'a NetworkApplication,
    initiator: &'a NetworkApplication,
) -> (&'a NetworkApplication, &'a NetworkApplication) {
    match node {
        RelativeNodeType::Receiver => (receiver, initiator),
        RelativeNodeType::Initiator => (initiator, receiver),
    }
}

async fn open_pair(
    receiver: &NetworkApplication,
    initiator: &NetworkApplication,
    topic: Topic,
) -> (OwnedMultiplexedSubscription, OwnedMultiplexedSubscription) {
    let (receiver, initiator) = (receiver.on(topic), initiator.on(topic));
    let (r, i) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(
            receiver.initiate_subscription(),
            initiator.initiate_subscription()
        )
    })
    .await
    .expect("the pair never opened");
    (r.unwrap(), i.unwrap())
}

async fn assert_same_channel(a: &OwnedMultiplexedSubscription, b: &OwnedMultiplexedSubscription) {
    assert_eq!(a.id(), b.id(), "the two ends opened different ids");
    for (from, to) in [(a, b), (b, a)] {
        from.send_to_peer(b"ping").await.unwrap();
        let got = tokio::time::timeout(HANG_GUARD, to.recv())
            .await
            .expect("a message never reached the other end");
        assert_eq!(&got.unwrap()[..], b"ping");
    }
}

/// The audit's scenario: one side's `sync()` is cut off by its stage timeout before the peer
/// makes any call, and both then open the next stage's subscription.
#[rstest]
#[case::receiver_alone(RelativeNodeType::Receiver)]
#[case::initiator_alone(RelativeNodeType::Initiator)]
#[tokio::test]
async fn a_cancelled_lone_sync_does_not_shift_later_pairings(#[case] lone: RelativeNodeType) {
    let (receiver, initiator, _link) = common::connected(WIRE).await;
    let (r, i) = open_pair(&receiver, &initiator, Topic::GENERAL).await;
    assert_same_channel(&r, &i).await;

    let (alone, _) = side(lone, &receiver, &initiator);
    assert!(
        alone.sync().now_or_never().is_none(),
        "a sync with no peer call cannot complete"
    );

    let (r, i) = open_pair(&receiver, &initiator, Topic::GENERAL).await;
    assert_same_channel(&r, &i).await;
}

/// One side's readiness sync is still waiting when the peer gives up on the stage and opens the
/// next one. The waiting call must not take the peer's next subscription, and still pairs with
/// the peer's sync on its own topic later.
#[rstest]
#[case::receiver_waiting(RelativeNodeType::Receiver)]
#[case::initiator_waiting(RelativeNodeType::Initiator)]
#[tokio::test]
async fn a_waiting_sync_does_not_take_the_peers_next_stage(#[case] waiting: RelativeNodeType) {
    let (receiver, initiator, _link) = common::connected(WIRE).await;
    let (alone, peer) = side(waiting, &receiver, &initiator);
    let alone_ready = alone.on(DIRECT_READY);
    let mut lone_sync = Box::pin(alone_ready.sync());

    // Polled first on every wake, so it sees each of the peer's opens before the next stage does.
    let (r, i) = tokio::time::timeout(HANG_GUARD, async {
        tokio::select! {
            biased;
            res = &mut lone_sync => panic!("the lone sync completed with no peer sync: {res:?}"),
            pair = open_pair(&receiver, &initiator, TURN) => pair,
        }
    })
    .await
    .expect("the next stage never opened while one side waited on the previous one");
    assert_same_channel(&r, &i).await;

    let peer_ready = peer.on(DIRECT_READY);
    let (lone, matched) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(lone_sync, peer_ready.sync())
    })
    .await
    .expect("the waiting sync never paired with the peer's");
    lone.unwrap();
    matched.unwrap();
}

/// However often a receiver's open is cancelled, it proposes one id, so the initiator serves one.
#[tokio::test]
async fn cancelled_receiver_opens_leave_one_proposal() {
    let (receiver, initiator, _link) = common::connected(WIRE).await;
    for _ in 0..3 {
        assert!(receiver.initiate_subscription().now_or_never().is_none());
    }

    let (r, i) = open_pair(&receiver, &initiator, Topic::GENERAL).await;
    assert_same_channel(&r, &i).await;

    // Everything the receiver sent before this pair has been read once it opens: a second
    // proposal for the general topic would be queued now and served at the first poll.
    let (r2, i2) = open_pair(&receiver, &initiator, TURN).await;
    assert_same_channel(&r2, &i2).await;
    assert!(
        initiator.initiate_subscription().now_or_never().is_none(),
        "the initiator was handed a second proposal from the cancelled opens"
    );
}
