//! Cancel-safety of the netbeam subscription pre-handshake (`initiate_subscription`) and of the
//! close sequence that follows it.
//!
//! Each hole-punch attempt runs under a timeout, so a handshake or a close may be dropped at any
//! await. These tests pin two properties on top of the resumable handshake (#324):
//!
//! 1. A close waiting for the peer's `PostDrop` never blocks this side's later handshakes.
//! 2. However many Receiver attempts are cancelled mid-echo, the Initiator is asked to serve
//!    exactly one `PreCreate`. That is what lets the connection's single reader hand `PreCreate`
//!    ids to the handshake through a channel of capacity 1 without ever waiting on it.
//!
//! Transport: an in-memory reliable ordered pipe, and the runtime clock is paused. Virtual time
//! advances only when every task is blocked with nothing in flight, so `DEADLOCK_PROBE` elapsing
//! proves the awaited event can never happen. It is not a latency bound.

use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Mutex;
use futures::FutureExt;
use netbeam::multiplex::OwnedMultiplexedSubscription;
use netbeam::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use netbeam::sync::network_application::NetworkApplication;
use netbeam::sync::subscription::{Subscribable, SubscriptionBiStream};
use netbeam::sync::RelativeNodeType;
use std::time::Duration;

const PRE_RESERVED: usize = 32;
const DEADLOCK_PROBE: Duration = Duration::from_secs(3600);

struct MemPipe {
    tx: UnboundedSender<Bytes>,
    rx: Mutex<UnboundedReceiver<Bytes>>,
}

#[async_trait]
impl ReliableOrderedStreamToTarget for MemPipe {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        self.tx
            .send(Bytes::copy_from_slice(input))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer dropped"))
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer dropped"))
    }
}

fn mem_pipe_pair() -> (MemPipe, MemPipe) {
    let (a_tx, a_rx) = unbounded_channel();
    let (b_tx, b_rx) = unbounded_channel();
    (
        MemPipe {
            tx: a_tx,
            rx: Mutex::new(b_rx),
        },
        MemPipe {
            tx: b_tx,
            rx: Mutex::new(a_rx),
        },
    )
}

/// Returns (receiver, initiator) plus both sides' pre-reserved subscriptions, kept alive so that
/// every later `initiate_subscription` performs the PreCreate handshake.
async fn connected_pair_past_prereserved() -> (
    NetworkApplication,
    NetworkApplication,
    Vec<OwnedMultiplexedSubscription>,
    Vec<OwnedMultiplexedSubscription>,
) {
    let (a, b) = mem_pipe_pair();
    let (receiver, initiator) = citadel_io::tokio::join!(
        NetworkApplication::register(RelativeNodeType::Receiver, a),
        NetworkApplication::register(RelativeNodeType::Initiator, b)
    );
    let (receiver, initiator) = (receiver.unwrap(), initiator.unwrap());
    let mut r_reserved = Vec::new();
    let mut i_reserved = Vec::new();
    for _ in 0..PRE_RESERVED {
        r_reserved.push(receiver.initiate_subscription().await.unwrap());
        i_reserved.push(initiator.initiate_subscription().await.unwrap());
    }
    (receiver, initiator, r_reserved, i_reserved)
}

/// Poll the Receiver's handshake exactly once (it sends `PreCreate` and parks waiting for the echo),
/// then drop it, as an outer timeout would.
fn cancel_receiver_handshake_mid_echo(receiver: &NetworkApplication) {
    let parked = receiver.initiate_subscription().now_or_never();
    assert!(
        parked.is_none(),
        "setup: the receiver handshake must be waiting for the echo when cancelled"
    );
}

/// A close waits for the peer's `PostDrop`, which the peer sends only once it drops its own end.
/// That wait must not hold up this side's later handshakes.
#[tokio::test(start_paused = true)]
async fn a_close_awaiting_the_peer_never_blocks_new_handshakes() {
    let (receiver, initiator, mut r_res, _i_res) = connected_pair_past_prereserved().await;

    // The Receiver closes its end; the Initiator keeps its end of the same id open. Let the close
    // run until it is parked waiting for the Initiator's PostDrop.
    drop(r_res.pop());
    citadel_io::tokio::time::sleep(DEADLOCK_PROBE).await;

    let (r_sub, i_sub) = citadel_io::tokio::time::timeout(DEADLOCK_PROBE, async {
        citadel_io::tokio::join!(
            receiver.initiate_subscription(),
            initiator.initiate_subscription()
        )
    })
    .await
    .expect(
        "no handshake can complete while a close awaits the peer: the close holds the post-close \
         map lock across its await, and every handshake needs that lock",
    );
    let (r_sub, i_sub) = (r_sub.unwrap(), i_sub.unwrap());
    assert_eq!(r_sub.id(), i_sub.id());
}

/// Cancelled Receiver attempts resume one id rather than each sending a `PreCreate` of its own, so
/// the Initiator has exactly one to serve and the Receiver can receive at most one echo per
/// handshake. Two queued echoes are what would park the connection's reader on the capacity-1
/// pre-action channel; this pins that they cannot arise.
#[tokio::test(start_paused = true)]
async fn cancelled_receiver_attempts_leave_one_precreate_in_flight() {
    let (receiver, initiator, r_res, i_res) = connected_pair_past_prereserved().await;

    cancel_receiver_handshake_mid_echo(&receiver);
    cancel_receiver_handshake_mid_echo(&receiver);

    let served =
        citadel_io::tokio::time::timeout(DEADLOCK_PROBE, initiator.initiate_subscription())
            .await
            .expect("the initiator was never asked to serve the cancelled attempts' id")
            .unwrap();
    assert!(
        citadel_io::tokio::time::timeout(DEADLOCK_PROBE, initiator.initiate_subscription())
            .await
            .is_err(),
        "the initiator served a second PreCreate: each cancelled receiver attempt sent its own id"
    );

    // The resumed Receiver handshake pairs with the one the Initiator served.
    let resumed =
        citadel_io::tokio::time::timeout(DEADLOCK_PROBE, receiver.initiate_subscription())
            .await
            .expect("the resumed receiver handshake never completed")
            .unwrap();
    assert_eq!(resumed.id(), served.id());
    resumed.send_serialized(7u64).await.unwrap();
    let got = citadel_io::tokio::time::timeout(DEADLOCK_PROBE, served.recv_serialized::<u64>())
        .await
        .expect("the resumed pair is not on the same channel");
    assert_eq!(got.unwrap(), 7);

    // And the connection's reader still delivers to an established subscription.
    i_res[0].send_serialized(42u64).await.unwrap();
    let got = citadel_io::tokio::time::timeout(DEADLOCK_PROBE, r_res[0].recv_serialized::<u64>())
        .await
        .expect("an established subscription stopped receiving");
    assert_eq!(got.unwrap(), 42);
}
