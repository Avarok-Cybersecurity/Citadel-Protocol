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
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::{watch, Mutex};
use futures::Future;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::reliable_conn::{ConnAddr, ReliableOrderedStreamToTarget};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
enum Frame {
    /// The sender is now on this attempt and has abandoned every earlier one.
    Attempt(usize),
    Data {
        attempt: usize,
        payload: Vec<u8>,
    },
}

pub(crate) struct AttemptCoordinator<S> {
    control: Arc<S>,
    lane: citadel_io::Mutex<Option<(usize, UnboundedSender<Vec<u8>>)>>,
    peer_attempt: watch::Sender<usize>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl<S: ReliableOrderedStreamToTarget + 'static> AttemptCoordinator<S> {
    pub(crate) fn new(control: S, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            control: Arc::new(control),
            lane: citadel_io::Mutex::new(None),
            peer_attempt: watch::channel(0).0,
            local_addr,
            peer_addr,
        }
    }

    /// Moves this side onto `attempt` and tells the peer. The lane is opened
    /// before the announcement, so the peer's first frame for it cannot arrive
    /// ahead of it; the previous lane closes, ending its attempt's reader.
    pub(crate) async fn enter(&self, attempt: usize) -> std::io::Result<AttemptLane<S>> {
        let (tx, rx) = unbounded_channel();
        *self.lane.lock() = Some((attempt, tx));
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
                    if let Some((current, tx)) = self.lane.lock().as_ref() {
                        if *current == attempt {
                            // A closed lane means its attempt already ended locally.
                            let _ = tx.send(payload);
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
    inbound: Mutex<UnboundedReceiver<Vec<u8>>>,
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
