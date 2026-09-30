//! A subscription attempt that is cancelled mid-handshake (every hole-punch
//! attempt runs under a timeout) must not shift the pairing of the attempts
//! that follow. If it does, the next attempt on each side opens a different
//! channel id, and whatever they exchange is dropped as "Channel ID does not
//! exist" until both give up.

use citadel_io::tokio;
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams;
use std::time::Duration;

/// Above the multiplexer's pre-reserved id count.
const PRE_RESERVED_BOUND: usize = 64;

#[tokio::test]
async fn a_cancelled_subscription_does_not_misalign_the_next_one() {
    let (receiver, initiator) = create_streams().await;

    // The first ids are pre-reserved and open without a handshake. Use them
    // up (in pairs, as both sides would) until the receiver has to ask the
    // initiator. That attempt goes unanswered and is abandoned, as a timed-out
    // hole-punch attempt is.
    let mut held = Vec::new();
    let mut abandoned_one = false;
    for _ in 0..(2 * PRE_RESERVED_BOUND) {
        match tokio::time::timeout(Duration::from_millis(500), receiver.initiate_subscription())
            .await
        {
            Ok(pre_reserved) => {
                held.push(pre_reserved.unwrap());
                held.push(initiator.initiate_subscription().await.unwrap());
            }
            Err(_) => {
                abandoned_one = true;
                break;
            }
        }
    }
    assert!(
        abandoned_one,
        "every subscription opened without a handshake, so nothing was cancelled"
    );

    // Both sides retry together.
    let (receiver_sub, initiator_sub) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            receiver.initiate_subscription(),
            initiator.initiate_subscription()
        )
    })
    .await
    .expect("the retried subscriptions never completed");
    let receiver_sub = receiver_sub.unwrap();
    let initiator_sub = initiator_sub.unwrap();

    receiver_sub.send_to_peer(b"ping").await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), initiator_sub.recv())
        .await
        .expect("the two sides of the retried subscription are on different channels");
    assert_eq!(&received.unwrap()[..], b"ping");

    initiator_sub.send_to_peer(b"pong").await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), receiver_sub.recv())
        .await
        .expect("the reply never reached the receiver");
    assert_eq!(&received.unwrap()[..], b"pong");
}
