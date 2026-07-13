//! Per-lock engine: owns the local voter (shared acceptor), the packet inbox task,
//! request/response correlation, and the local monotonic clock epoch. The typed
//! facades ([`crate::sync::group::mutex`], [`crate::sync::group::rwlock`]) wrap an
//! `Arc<Engine>`; all protocol decisions are delegated to the pure core modules.

use crate::sync::group::acceptor::{Acceptor, AcceptorStateStore};
use crate::sync::group::admission;
use crate::sync::group::config::GroupLockConfig;
use crate::sync::group::engine_util::PendingRound;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::op_types::OpDenied;
use crate::sync::group::record::LockRecord;
use crate::sync::group::transport::GroupTransport;
use crate::sync::group::wire::{Ballot, GroupMsg, GroupPacket};
use crate::sync::group::{LockId, MemberId};
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Notify;
use citadel_io::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Remote ballots may run ahead of ours, but a counter absurdly far ahead can only
/// be a hostile attempt to exhaust the u64 space and wedge future proposals.
const BALLOT_PLAUSIBILITY_WINDOW: u64 = 1 << 32;

pub(crate) struct Engine {
    pub(crate) cfg: GroupLockConfig,
    /// Config digest folded with the value-type tag (see `create.rs`).
    wire_digest: u64,
    pub(crate) lock_id: LockId,
    pub(crate) transport: Arc<GroupTransport>,
    acceptor: Mutex<Acceptor>,
    store: Arc<dyn AcceptorStateStore>,
    pub(crate) pending: Mutex<HashMap<u64, UnboundedSender<(MemberId, GroupMsg)>>>,
    req_ctr: AtomicU64,
    /// Highest ballot counter observed anywhere; the next proposal exceeds it.
    pub(crate) ballot_ctr: AtomicU64,
    /// Woken by inbound `Nudge`s (a queue entry may have become admissible).
    pub(crate) nudge: Notify,
    epoch: Instant,
    shutdown: Notify,
}

impl Engine {
    pub(crate) fn new(
        transport: Arc<GroupTransport>,
        lock_id: LockId,
        cfg: GroupLockConfig,
        wire_digest: u64,
        store: Arc<dyn AcceptorStateStore>,
    ) -> Result<Arc<Self>, GroupLockError> {
        let inbox = transport
            .register_lock(lock_id, wire_digest)
            .ok_or_else(|| {
                GroupLockError::InvalidConfig(format!(
                    "lock id {lock_id:?} already registered on this transport"
                ))
            })?;
        let acceptor = store
            .load(lock_id)
            .map(Acceptor::from_persisted)
            .unwrap_or_default();
        let this = Arc::new(Self {
            cfg,
            wire_digest,
            lock_id,
            transport,
            acceptor: Mutex::new(acceptor),
            store,
            pending: Mutex::new(HashMap::new()),
            req_ctr: AtomicU64::new(0),
            ballot_ctr: AtomicU64::new(0),
            nudge: Notify::new(),
            epoch: Instant::now(),
            shutdown: Notify::new(),
        });
        let task = this.clone();
        citadel_io::spawn(async move { task.inbox_loop(inbox).await });
        Ok(this)
    }

    /// Milliseconds on the local monotonic clock since engine creation.
    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn next_req_id(&self) -> u64 {
        self.req_ctr.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// RAII: the pending-map entry is removed on drop, so a cancelled proposer
    /// future cannot leak its response channel.
    pub(crate) fn register_pending(&self, req_id: u64) -> PendingRound<'_> {
        let (tx, rx) = unbounded_channel();
        let _ = self.pending.lock().insert(req_id, tx);
        PendingRound {
            engine: self,
            req_id,
            rx,
        }
    }

    pub(crate) fn remote_members(&self) -> impl Iterator<Item = MemberId> + '_ {
        let local = self.cfg.local_id();
        self.cfg
            .members()
            .iter()
            .copied()
            .filter(move |m| *m != local)
    }

    pub(crate) fn packet(&self, req_id: u64, msg: GroupMsg) -> GroupPacket {
        GroupPacket {
            lock_id: self.lock_id,
            from: self.cfg.local_id(),
            req_id,
            config_digest: self.wire_digest,
            msg,
        }
    }

    pub(crate) fn broadcast(&self, req_id: u64, msg: &GroupMsg) {
        for member in self.remote_members() {
            let pkt = self.packet(req_id, msg.clone());
            self.transport.send_to(member, &pkt);
        }
    }

    /// The local member's vote, identical in behavior to a remote voter.
    /// Persists acceptor state before returning the reply (write-before-reply).
    pub(crate) fn local_vote(&self, msg: &GroupMsg) -> Option<GroupMsg> {
        let mut acc = self.acceptor.lock();
        let reply = Self::vote(&mut acc, msg)?;
        self.store.save(self.lock_id, acc.state());
        Some(reply)
    }

    /// Track the highest ballot counter seen so future proposals exceed it.
    /// Returns `false` (and does not advance) for implausibly large counters —
    /// a hostile peer must not be able to exhaust the ballot space.
    pub(crate) fn observe_ballot(&self, ballot: Ballot) -> bool {
        let local = self.ballot_ctr.load(Ordering::Relaxed);
        if ballot.counter > local.saturating_add(BALLOT_PLAUSIBILITY_WINDOW) {
            log::warn!(target: "citadel", "[GroupLock] dropping implausible ballot {ballot:?} (local {local})");
            return false;
        }
        self.ballot_ctr.fetch_max(ballot.counter, Ordering::Relaxed);
        true
    }

    async fn inbox_loop(self: Arc<Self>, mut inbox: UnboundedReceiver<GroupPacket>) {
        loop {
            let packet = citadel_io::tokio::select! {
                p = inbox.recv() => match p { Some(p) => p, None => break },
                _ = self.shutdown.notified() => break,
            };
            match &packet.msg {
                GroupMsg::Nudge => {
                    self.nudge.notify_waiters();
                }
                msg if msg.is_voter_request() => {
                    if !self.msg_sane(msg) {
                        log::warn!(target: "citadel", "[GroupLock] dropping insane voter request from {:?}", packet.from);
                        continue;
                    }
                    if let GroupMsg::Prepare { ballot } | GroupMsg::Accept { ballot, .. } = msg {
                        if !self.observe_ballot(*ballot) {
                            continue;
                        }
                    }
                    if let Some(reply) = self.local_vote(msg) {
                        let out = self.packet(packet.req_id, reply);
                        self.transport.send_to(packet.from, &out);
                    }
                }
                _ => {
                    // response for a pending proposer round / hint gather
                    if !self.msg_sane(&packet.msg) {
                        log::warn!(target: "citadel", "[GroupLock] dropping insane response from {:?}", packet.from);
                        continue;
                    }
                    if let GroupMsg::PrepareNack { promised, .. }
                    | GroupMsg::AcceptNack { promised, .. } = &packet.msg
                    {
                        let _ = self.observe_ballot(*promised);
                    }
                    let tx = self.pending.lock().get(&packet.req_id).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send((packet.from, packet.msg));
                    }
                }
            }
        }
        log::trace!(target: "citadel", "[GroupLock] engine inbox loop for {:?} ended", self.lock_id);
    }

    /// Nudges every member whose queue entry may have become admissible in `record`.
    pub(crate) fn nudge_next(&self, record: &LockRecord) {
        for member in admission::next_grants(record) {
            if member == self.cfg.local_id() {
                self.nudge.notify_waiters();
            } else {
                let pkt = self.packet(0, GroupMsg::Nudge);
                self.transport.send_to(member, &pkt);
            }
        }
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown.notify_waiters();
        self.transport.unregister_lock(self.lock_id);
    }
}

/// Maps a denial that terminates an op to the public error space.
pub(crate) fn denial_to_error(denied: OpDenied) -> GroupLockError {
    match denied {
        OpDenied::Uninitialized => GroupLockError::Uninitialized,
        OpDenied::WouldBlock => GroupLockError::WouldBlock,
        other => GroupLockError::Io(format!("unexpected op denial: {other:?}")),
    }
}
