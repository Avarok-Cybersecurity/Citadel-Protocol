//! A synchronized start must not wait on the peer's clock. The receiver once sent its own wall
//! clock's start time, so a receiver whose clock ran ahead (or that claimed so) held the
//! initiator back by the whole lead, and a lead of a few seconds broke the hole punch timed by it.
//! Now the receiver sends a delay relative to receipt, and the initiator bounds it.

mod common;

use citadel_io::tokio;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::sync_start::MAX_SYNC_START_DELAY;
use netbeam::sync::wire::WireRevision;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// netbeam's private `SyncPacket<()>`, variant for variant.
#[derive(Serialize, Deserialize)]
enum SyncPacket {
    Syn(()),
    SynAck(()),
    Ack(i64),
    AckAfter(u64),
}

const CLAIMED_DELAY: Duration = Duration::from_secs(4);

/// The clock is paused: time advances only while every task waits, so the measured wait is
/// exactly what the initiator chose to sleep.
#[tokio::test(start_paused = true)]
async fn the_initiator_bounds_the_delay_the_receiver_asks_for() {
    let (receiver, initiator, _link) = common::connected(WireRevision::Exchanged).await;

    let fake_receiver = async {
        let sub = receiver.initiate_subscription().await.unwrap();
        sub.send_serialized(SyncPacket::Syn(())).await.unwrap();
        let reply: SyncPacket = sub.recv_serialized().await.unwrap();
        assert!(matches!(reply, SyncPacket::SynAck(())));
        let asked = CLAIMED_DELAY.as_nanos() as u64;
        sub.send_serialized(SyncPacket::AckAfter(asked))
            .await
            .unwrap();
        // Holds the subscription open until the initiator is done.
        std::future::pending::<()>().await
    };

    let measured = async {
        let started = tokio::time::Instant::now();
        initiator.sync().await.unwrap();
        started.elapsed()
    };

    let waited = tokio::select! {
        waited = measured => waited,
        _ = fake_receiver => unreachable!(),
    };
    assert!(
        waited <= MAX_SYNC_START_DELAY,
        "the initiator waited {waited:?} because the peer asked for {CLAIMED_DELAY:?}"
    );
}

/// Both ends of an honest sync start together, whatever the round trip.
#[tokio::test(start_paused = true)]
async fn both_ends_still_start_together() {
    let (receiver, initiator, _link) = common::connected(WireRevision::Exchanged).await;
    let started = tokio::time::Instant::now();
    let (r, i) = tokio::join!(
        async {
            receiver.sync().await.unwrap();
            started.elapsed()
        },
        async {
            initiator.sync().await.unwrap();
            started.elapsed()
        }
    );
    assert_eq!(r, i, "the two ends started {:?} apart", r.abs_diff(i));
}
