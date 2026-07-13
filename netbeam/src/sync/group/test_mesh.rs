//! In-memory full-mesh builder for tests and examples: n members wired with
//! severable in-memory pipes, enabling deterministic fault injection (partitions,
//! isolated members ≈ crashed members) without sockets.

use crate::reliable_conn::ReliableOrderedStreamToTarget;
use crate::sync::group::transport::GroupTransport;
use crate::sync::group::MemberId;
use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// One direction of an in-memory link. `severed` is shared by both directions of
/// the pair: while set, sends fail (as a broken transport would) — in-flight
/// messages already queued still deliver, mimicking real partition onset.
pub struct InMemoryPipe {
    tx: UnboundedSender<Vec<u8>>,
    rx: Mutex<UnboundedReceiver<Vec<u8>>>,
    severed: Arc<AtomicBool>,
}

#[async_trait]
impl ReliableOrderedStreamToTarget for InMemoryPipe {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        if self.severed.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "link severed",
            ));
        }
        self.tx.send(input.to_vec()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer receiver dropped")
        })
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .map(Bytes::from)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed"))
    }
}

/// A full mesh of `n` members with per-pair severable links.
pub struct TestMesh {
    transports: HashMap<MemberId, Arc<GroupTransport>>,
    links: HashMap<(MemberId, MemberId), Arc<AtomicBool>>,
}

impl TestMesh {
    pub fn new(member_ids: &[MemberId]) -> Self {
        let mut endpoints: HashMap<
            MemberId,
            HashMap<MemberId, Arc<dyn ReliableOrderedStreamToTarget + 'static>>,
        > = member_ids.iter().map(|m| (*m, HashMap::new())).collect();
        let mut links = HashMap::new();

        for (i, a) in member_ids.iter().enumerate() {
            for b in &member_ids[i + 1..] {
                let severed = Arc::new(AtomicBool::new(false));
                let (tx_ab, rx_ab) = unbounded_channel();
                let (tx_ba, rx_ba) = unbounded_channel();
                let pipe_a = InMemoryPipe {
                    tx: tx_ab,
                    rx: Mutex::new(rx_ba),
                    severed: severed.clone(),
                };
                let pipe_b = InMemoryPipe {
                    tx: tx_ba,
                    rx: Mutex::new(rx_ab),
                    severed: severed.clone(),
                };
                endpoints.get_mut(a).unwrap().insert(*b, Arc::new(pipe_a));
                endpoints.get_mut(b).unwrap().insert(*a, Arc::new(pipe_b));
                links.insert(Self::key(*a, *b), severed);
            }
        }

        let transports = endpoints
            .into_iter()
            .map(|(id, peers)| (id, GroupTransport::new(id, peers)))
            .collect();
        Self { transports, links }
    }

    fn key(a: MemberId, b: MemberId) -> (MemberId, MemberId) {
        if a <= b {
            (a, b)
        } else {
            (b, a)
        }
    }

    pub fn transport(&self, id: MemberId) -> Arc<GroupTransport> {
        self.transports
            .get(&id)
            .expect("member not in mesh")
            .clone()
    }

    /// Sets/clears the severed state of the `a<->b` link (both directions).
    pub fn set_link_severed(&self, a: MemberId, b: MemberId, severed: bool) {
        self.links
            .get(&Self::key(a, b))
            .expect("link not in mesh")
            .store(severed, Ordering::Release);
    }

    /// Severs every link touching `id`. An isolated member cannot renew or refresh,
    /// so from the group's perspective it is indistinguishable from a crash — the
    /// standard way to "kill" a member in fault-injection tests.
    pub fn isolate(&self, id: MemberId) {
        for (pair, flag) in &self.links {
            if pair.0 == id || pair.1 == id {
                flag.store(true, Ordering::Release);
            }
        }
    }

    /// Heals every link touching `id` (partition recovery).
    pub fn rejoin(&self, id: MemberId) {
        for (pair, flag) in &self.links {
            if pair.0 == id || pair.1 == id {
                flag.store(false, Ordering::Release);
            }
        }
    }

    /// Partitions the mesh into two sides: every cross-side link is severed.
    pub fn partition(&self, side_a: &[MemberId], side_b: &[MemberId]) {
        for a in side_a {
            for b in side_b {
                self.set_link_severed(*a, *b, true);
            }
        }
    }

    /// Heals all links in the mesh.
    pub fn heal_all(&self) {
        for flag in self.links.values() {
            flag.store(false, Ordering::Release);
        }
    }
}
