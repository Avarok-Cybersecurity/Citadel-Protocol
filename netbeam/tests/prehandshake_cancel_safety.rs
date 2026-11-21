//! Cancel-safety of the netbeam subscription pre-handshake (`initiate_subscription`) and of the
//! close sequence that follows it.
//!
//! Each hole-punch attempt runs under a timeout, so a handshake or a close may be dropped at any
//! await. This pins that a close waiting for the peer's `PostDrop` never blocks this side's later
//! handshakes.
//!
//! Transport: an in-memory reliable ordered pipe, and the runtime clock is paused. Virtual time
//! advances only when every task is blocked with nothing in flight, so `DEADLOCK_PROBE` elapsing
//! proves the awaited event can never happen. It is not a latency bound.

use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Mutex;
use netbeam::multiplex::OwnedMultiplexedSubscription;
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::network_application::NetworkApplication;
use netbeam::sync::subscription::{Subscribable, SubscriptionBiStream};
use netbeam::sync::wire::WireRevision;
use netbeam::sync::RelativeNodeType;
use std::time::Duration;

const WIRE: WireRevision = WireRevision::Exchanged;
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

/// Returns (receiver, initiator) and one paired subscription on each side.
async fn connected_pair_with_a_subscription() -> (
    NetworkApplication,
    NetworkApplication,
    OwnedMultiplexedSubscription,
    OwnedMultiplexedSubscription,
) {
    let (a, b) = mem_pipe_pair();
    let (receiver, initiator) = citadel_io::tokio::join!(
        NetworkApplication::register(RelativeNodeType::Receiver, a, WIRE),
        NetworkApplication::register(RelativeNodeType::Initiator, b, WIRE)
    );
    let (receiver, initiator) = (receiver.unwrap(), initiator.unwrap());
    let (r_sub, i_sub) = citadel_io::tokio::join!(
        receiver.initiate_subscription(),
        initiator.initiate_subscription()
    );
    (receiver, initiator, r_sub.unwrap(), i_sub.unwrap())
}

/// A close waits for the peer's `PostDrop`, which the peer sends only once it drops its own end.
/// That wait must not hold up this side's later handshakes.
#[tokio::test(start_paused = true)]
async fn a_close_awaiting_the_peer_never_blocks_new_handshakes() {
    let (receiver, initiator, r_open, _i_open) = connected_pair_with_a_subscription().await;

    // The Receiver closes its end; the Initiator keeps its end of the same id open. Let the close
    // run until it is parked waiting for the Initiator's PostDrop.
    drop(r_open);
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
