//! Keeps both sides of a hole punch on the same attempt.
//!
//! Each side bounds an attempt with its own timer, so after a one-sided delay
//! the two sides give up at different moments. Without an attempt number on
//! the wire, a side that gave up started its next attempt against a peer still
//! inside the previous one, and the two then ran every later attempt at the
//! same offset until the retries were gone.
//!
//! Here each side announces the attempt it is on over one control stream, and
//! an attempt runs only once both sides are on it. A side that abandons an
//! attempt announces the next one, which ends the peer's copy too, so the two
//! always retry together. Each attempt's traffic travels in its own lane,
//! tagged with its number, so nothing an abandoned attempt left in flight can
//! reach a later one.

use bytes::Bytes;
use citadel_io::tokio::sync::mpsc::{channel, Receiver, Sender};
use citadel_io::tokio::sync::{watch, Mutex};
use futures::Future;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::reliable_conn::{ConnAddr, ReliableOrderedStreamToTarget};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

/// Frames the router may hold for one attempt before it stops reading the
/// control stream until that attempt reads them or ends.
///
/// A memory bound, not a correctness bound: any capacity of at least one is
/// correct, because the router's wait for room is itself bounded by the lane's
/// attempt (see [`AttemptCoordinator::route_inbound`]). The lane's reader is
/// the attempt's own multiplexer, which forwards each frame without waiting on
/// the application, so in the normal case the router never waits at all.
pub(crate) const LANE_CAPACITY: usize = 16;

#[derive(Serialize, Deserialize)]
pub(crate) enum Frame {
    /// The sender is now on this attempt and has abandoned every earlier one.
    Attempt(usize),
    Data {
        attempt: usize,
        payload: Vec<u8>,
    },
}

pub(crate) struct AttemptCoordinator<S> {
    control: Arc<S>,
    lane: citadel_io::Mutex<Option<(usize, Sender<Vec<u8>>)>>,
    local_attempt: watch::Sender<usize>,
    peer_attempt: watch::Sender<usize>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl<S: ReliableOrderedStreamToTarget + 'static> AttemptCoordinator<S> {
    pub(crate) fn new(control: S, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            control: Arc::new(control),
            lane: citadel_io::Mutex::new(None),
            local_attempt: watch::channel(0).0,
            peer_attempt: watch::channel(0).0,
            local_addr,
            peer_addr,
        }
    }

    /// Moves this side onto `attempt` and tells the peer. The lane is opened
    /// before the announcement, so the peer's first frame for it cannot arrive
    /// ahead of it; the previous lane closes, ending its attempt's reader.
    pub(crate) async fn enter(&self, attempt: usize) -> std::io::Result<AttemptLane<S>> {
        let (tx, rx) = channel(LANE_CAPACITY);
        *self.lane.lock() = Some((attempt, tx));
        self.local_attempt.send_replace(attempt);
        self.control
            .send_serialized(Frame::Attempt(attempt))
            .await?;
        Ok(AttemptLane {
            control: self.control.clone(),
            attempt,
            inbound: Mutex::new(rx),
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        })
    }

    /// Resolves with the peer's attempt once it has announced `attempt` or a later one.
    pub(crate) async fn peer_reached(&self, attempt: usize) -> usize {
        let mut rx = self.peer_attempt.subscribe();
        let reached = match rx.wait_for(|peer| *peer >= attempt).await {
            Ok(peer) => *peer,
            // The sender is owned by `self`, which outlives this borrow.
            Err(_) => unreachable!("peer_attempt sender dropped while borrowed"),
        };
        reached
    }

    /// Routes the control stream's frames; returns only when the stream fails.
    ///
    /// A full lane stops the routing, so the peer cannot grow this side's
    /// memory. The wait ends when the lane's reader makes room, or when this
    /// side leaves that attempt: the frame is then dropped, as its attempt has
    /// ended locally. Both are bounded by the attempt's own timeout, so the wait
    /// cannot outlive the attempt it serves.
    pub(crate) async fn route_inbound(&self) -> std::io::Error {
        loop {
            match self.control.recv_serialized::<Frame>().await {
                Ok(Frame::Attempt(attempt)) => {
                    self.peer_attempt.send_if_modified(|peer| {
                        let advanced = attempt > *peer;
                        if advanced {
                            *peer = attempt;
                        }
                        advanced
                    });
                }
                Ok(Frame::Data { attempt, payload }) => {
                    let lane = self
                        .lane
                        .lock()
                        .as_ref()
                        .filter(|(current, _)| *current == attempt)
                        .map(|(_, tx)| tx.clone());
                    if let Some(tx) = lane {
                        let mut local = self.local_attempt.subscribe();
                        citadel_io::tokio::select! {
                            // A closed lane means its attempt already ended locally.
                            _ = tx.send(payload) => {}
                            _ = local.wait_for(|current| *current != attempt) => {}
                        }
                    }
                }
                Err(err) => return err,
            }
        }
    }
}

/// One attempt's view of the control stream.
pub(crate) struct AttemptLane<S> {
    control: Arc<S>,
    attempt: usize,
    inbound: Mutex<Receiver<Vec<u8>>>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

type IoFuture<'a, T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

// Written out rather than through `#[async_trait]`: netbeam declares the trait
// with `async-trait`, which this crate does not depend on.
impl<S: ReliableOrderedStreamToTarget + 'static> ReliableOrderedStreamToTarget for AttemptLane<S> {
    fn send_to_peer<'a, 'b, 'r>(&'a self, input: &'b [u8]) -> IoFuture<'r, ()>
    where
        'a: 'r,
        'b: 'r,
        Self: 'r,
    {
        Box::pin(async move {
            let frame = Frame::Data {
                attempt: self.attempt,
                payload: input.to_vec(),
            };
            self.control.send_serialized(frame).await
        })
    }

    fn recv<'a, 'r>(&'a self) -> IoFuture<'r, Bytes>
    where
        'a: 'r,
        Self: 'r,
    {
        Box::pin(async move {
            self.inbound
                .lock()
                .await
                .recv()
                .await
                .map(Bytes::from)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "hole-punch attempt abandoned",
                    )
                })
        })
    }
}

impl<S> ConnAddr for AttemptLane<S> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

#[cfg(test)]
mod lane_bound_tests {
    use super::{AttemptCoordinator, Frame, IoFuture, LANE_CAPACITY};
    use bytes::Bytes;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use citadel_io::tokio::sync::Mutex;
    use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Elapses only once every task is blocked (the clock is paused), so it
    /// proves quiescence. Not a latency bound.
    const QUIESCENT: Duration = Duration::from_secs(3600);
    /// Far more frames than one lane may hold.
    const FLOOD: usize = LANE_CAPACITY * 8;

    /// The control stream as this side sees it: counts what the peer sent that
    /// this side has not read yet.
    struct CountingPipe {
        outbound: UnboundedSender<Vec<u8>>,
        inbound: Mutex<UnboundedReceiver<Vec<u8>>>,
        unread: Arc<AtomicUsize>,
    }

    impl ReliableOrderedStreamToTarget for CountingPipe {
        fn send_to_peer<'a, 'b, 'r>(&'a self, input: &'b [u8]) -> IoFuture<'r, ()>
        where
            'a: 'r,
            'b: 'r,
            Self: 'r,
        {
            Box::pin(async move {
                let _ = self.outbound.send(input.to_vec());
                Ok(())
            })
        }

        fn recv<'a, 'r>(&'a self) -> IoFuture<'r, Bytes>
        where
            'a: 'r,
            Self: 'r,
        {
            Box::pin(async move {
                let frame = self.inbound.lock().await.recv().await.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "closed")
                })?;
                self.unread.fetch_sub(1, Ordering::SeqCst);
                Ok(Bytes::from(frame))
            })
        }
    }

    /// A peer that floods an attempt this side is not reading must not grow
    /// this side's memory: the router stops reading the control stream once the
    /// lane is full. And that wait must end with the attempt, so the router then
    /// sees the peer's next announcement.
    #[tokio::test(start_paused = true)]
    async fn a_flooded_lane_holds_back_the_router_until_its_attempt_ends() {
        let (peer_tx, inbound) = unbounded_channel();
        let (outbound, _peer_rx) = unbounded_channel();
        let unread = Arc::new(AtomicUsize::new(0));
        let addr = "127.0.0.1:1".parse().unwrap();
        let attempts = AttemptCoordinator::new(
            CountingPipe {
                outbound,
                inbound: Mutex::new(inbound),
                unread: unread.clone(),
            },
            addr,
            addr,
        );
        let peer_send = |frame: Frame| {
            unread.fetch_add(1, Ordering::SeqCst);
            peer_tx.send(bincode::serialize(&frame).unwrap()).unwrap();
        };

        // Kept alive and never read: a reader that outlives its attempt, as the
        // attempt's multiplexer task can.
        let _stuck_reader = attempts.enter(1).await.unwrap();
        peer_send(Frame::Attempt(1));
        for _ in 0..FLOOD {
            peer_send(Frame::Data {
                attempt: 1,
                payload: vec![0; 64],
            });
        }
        peer_send(Frame::Attempt(2));

        let router = attempts.route_inbound();
        futures::pin_mut!(router);
        tokio::select! {
            err = &mut router => panic!("the control stream failed: {err}"),
            _ = tokio::time::sleep(QUIESCENT) => {}
        }
        // Read: Attempt(1), LANE_CAPACITY frames into the lane, and the one the
        // router is waiting to place.
        assert_eq!(
            unread.load(Ordering::SeqCst),
            FLOOD + 2 - (LANE_CAPACITY + 2),
            "the router kept reading the control stream into a lane nobody reads"
        );

        // This side leaves attempt 1: the held frame and the rest are dropped,
        // and the router reaches the peer's announcement of attempt 2.
        let _next = attempts.enter(2).await.unwrap();
        tokio::select! {
            err = &mut router => panic!("the control stream failed: {err}"),
            reached = attempts.peer_reached(2) => assert_eq!(reached, 2),
            _ = tokio::time::sleep(QUIESCENT) => {
                panic!("the router stayed blocked on the lane of an attempt that had ended")
            }
        }
        assert_eq!(unread.load(Ordering::SeqCst), 0);
    }
}
