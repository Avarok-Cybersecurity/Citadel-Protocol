//! Group mesh transport: routes [`GroupPacket`]s between the local member and its
//! peers over caller-supplied point-to-point reliable ordered streams. netbeam never
//! dials; the consumer wires the full mesh (and may heal it via
//! [`GroupTransport::replace_peer_stream`] after a reconnect).
//!
//! This layer performs no protocol decisions: it serializes, demultiplexes by
//! [`LockId`], and drops packets whose config digest mismatches the registered lock.

use crate::reliable_conn::ReliableOrderedStreamToTarget;
use crate::sync::group::wire::GroupPacket;
use crate::sync::group::{LockId, MemberId};
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::watch;
use citadel_io::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

struct PeerConn {
    conn: Arc<dyn ReliableOrderedStreamToTarget + 'static>,
    generation: u64,
    /// Dropped/renewed when the peer stream is replaced; the recv loop selects on
    /// it so a superseded or shut-down loop terminates instead of parking forever.
    stop_tx: watch::Sender<bool>,
}

struct LockChannel {
    tx: UnboundedSender<GroupPacket>,
    config_digest: u64,
}

pub struct GroupTransport {
    local_id: MemberId,
    peers: RwLock<HashMap<MemberId, PeerConn>>,
    locks: RwLock<HashMap<LockId, LockChannel>>,
    generation_ctr: AtomicU64,
}

impl GroupTransport {
    /// `peers` must contain one reliable ordered stream per remote member of every
    /// group this transport will serve. Spawns one receive loop per peer.
    pub fn new(
        local_id: MemberId,
        peers: HashMap<MemberId, Arc<dyn ReliableOrderedStreamToTarget + 'static>>,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            local_id,
            peers: RwLock::new(HashMap::new()),
            locks: RwLock::new(HashMap::new()),
            generation_ctr: AtomicU64::new(0),
        });
        for (id, conn) in peers {
            this.install_peer(id, conn);
        }
        this
    }

    pub fn local_id(&self) -> MemberId {
        self.local_id
    }

    /// Replaces (or installs) the stream to `peer` — the healing hook for members
    /// that reconnect after a network partition. The old receive loop retires on its
    /// next packet (generation check) or stream error.
    pub fn replace_peer_stream(
        self: &Arc<Self>,
        peer: MemberId,
        conn: Arc<dyn ReliableOrderedStreamToTarget + 'static>,
    ) {
        self.install_peer(peer, conn);
    }

    fn install_peer(
        self: &Arc<Self>,
        peer: MemberId,
        conn: Arc<dyn ReliableOrderedStreamToTarget + 'static>,
    ) {
        let generation = self.generation_ctr.fetch_add(1, Ordering::Relaxed) + 1;
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let previous = self.peers.write().insert(
            peer,
            PeerConn {
                conn: conn.clone(),
                generation,
                stop_tx,
            },
        );
        if let Some(previous) = previous {
            // wake the superseded loop even if its stream never yields again
            let _ = previous.stop_tx.send_replace(true);
        }
        let this = self.clone();
        citadel_io::spawn(async move {
            loop {
                let bytes = citadel_io::tokio::select! {
                    r = conn.recv() => match r {
                        Ok(b) => b,
                        Err(err) => {
                            log::trace!(target: "citadel", "[GroupTransport] recv loop for peer {peer:?} ended: {err:?}");
                            break;
                        }
                    },
                    _ = stop_rx.changed() => break,
                };
                // belt-and-braces: never route a packet read under a stale generation
                let current = this.peers.read().get(&peer).map(|p| p.generation);
                if current != Some(generation) {
                    break;
                }
                match bincode::deserialize::<GroupPacket>(&bytes) {
                    Ok(packet) => this.route(peer, packet),
                    Err(err) => {
                        log::warn!(target: "citadel", "[GroupTransport] malformed packet from {peer:?}: {err}")
                    }
                }
            }
        });
    }

    /// Stops every peer receive loop and drops the stream handles. Call when the
    /// mesh is done (engines unregister their locks independently); without this,
    /// the loop tasks hold `Arc<GroupTransport>` + stream references alive.
    pub fn shutdown(&self) {
        let mut peers = self.peers.write();
        for (_, peer) in peers.drain() {
            let _ = peer.stop_tx.send_replace(true);
        }
    }

    fn route(&self, peer: MemberId, packet: GroupPacket) {
        if packet.from != peer {
            log::warn!(target: "citadel", "[GroupTransport] origin mismatch: stream {peer:?} claimed {:?}; dropping", packet.from);
            return;
        }
        let locks = self.locks.read();
        let Some(channel) = locks.get(&packet.lock_id) else {
            log::trace!(target: "citadel", "[GroupTransport] no lock registered for {:?}; dropping", packet.lock_id);
            return;
        };
        if channel.config_digest != packet.config_digest {
            log::warn!(target: "citadel", "[GroupTransport] config digest mismatch from {peer:?} on {:?}; dropping (split config?)", packet.lock_id);
            return;
        }
        let _ = channel.tx.send(packet);
    }

    /// Registers a lock engine's inbox. Fails if the id is already registered.
    pub(crate) fn register_lock(
        &self,
        lock_id: LockId,
        config_digest: u64,
    ) -> Option<UnboundedReceiver<GroupPacket>> {
        let mut locks = self.locks.write();
        if locks.contains_key(&lock_id) {
            return None;
        }
        let (tx, rx) = unbounded_channel();
        locks.insert(lock_id, LockChannel { tx, config_digest });
        Some(rx)
    }

    pub(crate) fn unregister_lock(&self, lock_id: LockId) {
        let _ = self.locks.write().remove(&lock_id);
    }

    /// Best-effort fire-and-forget send. Failures are logged (a dead peer simply
    /// contributes no vote; safety never depends on delivery).
    pub(crate) fn send_to(&self, peer: MemberId, packet: &GroupPacket) {
        let Some(conn) = self.peers.read().get(&peer).map(|p| p.conn.clone()) else {
            log::trace!(target: "citadel", "[GroupTransport] no stream to {peer:?}");
            return;
        };
        let bytes = match bincode::serialize(packet) {
            Ok(b) => b,
            Err(err) => {
                log::warn!(target: "citadel", "[GroupTransport] serialize failure: {err}");
                return;
            }
        };
        citadel_io::spawn(async move {
            if let Err(err) = conn.send_to_peer(&bytes).await {
                log::trace!(target: "citadel", "[GroupTransport] send to {peer:?} failed: {err:?}");
            }
        });
    }
}
