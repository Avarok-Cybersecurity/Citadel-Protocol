//! Serializable group state: a byte-exportable [`AcceptorStateStore`] so members can
//! persist their voter state (promises + last accepted record, which embeds the
//! protected value) and resume after a full-group shutdown.
//!
//! Recovery semantics (honest version):
//! - A member restored via [`SnapshotAcceptorStore::from_bytes`] rejoins as a voter
//!   with its promises intact — the crash-recovery requirement quorum intersection
//!   depends on.
//! - Once any MAJORITY of restored members is back, the last committed value is
//!   recovered exactly (every committed round lives on a majority, and any two
//!   majorities intersect).
//! - A lone returning member can [`peek_value`] its last locally-accepted state
//!   immediately — its best known snapshot, which is guaranteed current if that
//!   member voted in the final committed round, but is otherwise possibly stale.
//!   Lock operations still require a majority.
//! - Durability boundary (SBIO): this store keeps state in memory and flags
//!   dirtiness; the CONSUMER exports [`SnapshotAcceptorStore::to_bytes`] and writes
//!   them wherever it likes. Exporting on graceful shutdown gives full-group-restart
//!   recovery. Strict crash-recovery (power loss mid-run) requires write-BEFORE-reply
//!   persistence: implement [`AcceptorStateStore`] directly over synchronous storage
//!   so `save` is durable before it returns.

use crate::sync::group::acceptor::{AcceptorStateStore, PersistedAcceptor};
use crate::sync::group::error::GroupLockError;
use crate::sync::group::record::LockRecord;
use crate::sync::group::{Fence, LockId};
use crate::sync::primitives::NetObject;
use citadel_io::tokio::sync::watch;
use citadel_io::RwLock;
use std::collections::HashMap;

/// In-memory store whose full contents round-trip through bytes, with a dirty
/// signal so consumers can persist on their own cadence.
pub struct SnapshotAcceptorStore {
    states: RwLock<HashMap<LockId, PersistedAcceptor>>,
    dirty_tx: watch::Sender<u64>,
}

impl Default for SnapshotAcceptorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotAcceptorStore {
    pub fn new() -> Self {
        let (dirty_tx, _) = watch::channel(0);
        Self {
            states: RwLock::new(HashMap::new()),
            dirty_tx,
        }
    }

    /// Restores a store previously exported with [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupLockError> {
        let states = bincode::deserialize::<HashMap<LockId, PersistedAcceptor>>(bytes)?;
        let this = Self::new();
        *this.states.write() = states;
        Ok(this)
    }

    /// Serializes the entire store (all locks). Route the bytes to your storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupLockError> {
        Ok(bincode::serialize(&*self.states.read())?)
    }

    /// A receiver that changes whenever acceptor state mutates (the value is a
    /// monotonic save counter). Consumers persist asynchronously off this signal;
    /// note the caveat in the module docs about async persistence vs crash safety.
    pub fn dirty_signal(&self) -> watch::Receiver<u64> {
        self.dirty_tx.subscribe()
    }

    /// This member's last locally-accepted record for `lock` — offline read, no
    /// quorum. Possibly stale relative to the true committed state; see module docs.
    pub fn peek_record(&self, lock: LockId) -> Option<LockRecord> {
        self.states
            .read()
            .get(&lock)
            .and_then(|s| s.accepted.as_ref())
            .map(|(_, rec)| rec.clone())
    }
}

impl AcceptorStateStore for SnapshotAcceptorStore {
    fn load(&self, lock: LockId) -> Option<PersistedAcceptor> {
        self.states.read().get(&lock).cloned()
    }

    fn save(&self, lock: LockId, state: &PersistedAcceptor) {
        let _ = self.states.write().insert(lock, state.clone());
        self.dirty_tx.send_modify(|n| *n = n.wrapping_add(1));
    }
}

/// Deserializes this member's last known value for `lock` from a store, without a
/// running group: `(value_version, value)`. `None` if the lock was never observed
/// initialized locally. Staleness caveat per the module docs.
pub fn peek_value<T: NetObject>(
    store: &SnapshotAcceptorStore,
    lock: LockId,
) -> Result<Option<(Fence, T)>, GroupLockError> {
    let Some(rec) = store.peek_record(lock) else {
        return Ok(None);
    };
    let value = bincode::deserialize::<T>(&rec.value)?;
    Ok(Some((rec.value_version, value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::group::acceptor::Acceptor;
    use crate::sync::group::wire::Ballot;
    use crate::sync::group::MemberId;

    fn stamped_store(value: u64) -> SnapshotAcceptorStore {
        let store = SnapshotAcceptorStore::new();
        let mut acc = Acceptor::default();
        let ballot = Ballot {
            counter: 3,
            proposer: MemberId(1),
        };
        acc.on_prepare(ballot);
        let mut rec = LockRecord::initial(bincode::serialize(&value).unwrap());
        rec.value_version = Fence(7);
        acc.on_accept(ballot, rec);
        store.save(LockId(42), acc.state());
        store
    }

    #[test]
    fn roundtrip_preserves_promises_and_value() {
        let store = stamped_store(1234);
        let restored = SnapshotAcceptorStore::from_bytes(&store.to_bytes().unwrap()).unwrap();
        // promise survives (the crash-recovery requirement)
        let state = restored.load(LockId(42)).unwrap();
        assert_eq!(
            state.promised,
            Some(Ballot {
                counter: 3,
                proposer: MemberId(1)
            })
        );
        // value is recoverable offline
        let (version, value) = peek_value::<u64>(&restored, LockId(42)).unwrap().unwrap();
        assert_eq!((version, value), (Fence(7), 1234));
        // unknown locks read as None, not an error
        assert!(peek_value::<u64>(&restored, LockId(9)).unwrap().is_none());
    }

    #[test]
    fn dirty_signal_fires_on_save() {
        let store = SnapshotAcceptorStore::new();
        let rx = store.dirty_signal();
        let before = *rx.borrow();
        store.save(LockId(1), &PersistedAcceptor::default());
        assert_ne!(*rx.borrow(), before);
    }
}
