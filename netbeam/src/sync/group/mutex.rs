//! N-node fault-tolerant mutex: the write-only facade over the group lock engine.
//!
//! ```ignore
//! let transport = GroupTransport::new(local_id, peer_streams);
//! let mutex = NetGroupMutex::<u64>::create(
//!     transport, LockId::from_name("counter"), cfg, store, Some(0)).await?;
//! let mut guard = mutex.lock().await?;
//! *guard += 1; // propagated to a majority atomically with the release
//! drop(guard);
//! ```
//!
//! Every member of the group must `create()` the lock (each runs a consensus voter);
//! exactly the configured `initial_value_owner` passes `Some(initial)`. Keep the
//! `NetGroupMutex` alive until all its guards are released: dropping it shuts down
//! the engine's message routing.

use crate::sync::group::acceptor::AcceptorStateStore;
use crate::sync::group::config::GroupLockConfig;
use crate::sync::group::engine::Engine;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::guard::NetGroupWriteGuard;
use crate::sync::group::transport::GroupTransport;
use crate::sync::group::{LockId, LockKind};
use crate::sync::primitives::NetObject;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

/// The guard returned by [`NetGroupMutex::lock`]. See [`NetGroupWriteGuard`] for the
/// fence/validity/recovery API. (`downgrade` is available but only meaningful for
/// groups that also use [`crate::sync::group::rwlock::NetGroupRwLock`] semantics.)
pub type NetGroupMutexGuard<T> = NetGroupWriteGuard<T>;

pub struct NetGroupMutex<T: NetObject> {
    engine: Arc<Engine>,
    _pd: PhantomData<fn() -> T>,
}

impl<T: NetObject> NetGroupMutex<T> {
    /// Joins (and on the owner, initializes) the distributed mutex `lock_id` over
    /// `transport`. Blocks until the initial value is established on a majority
    /// (bounded by `cfg.acquire_timeout()`).
    pub async fn create(
        transport: Arc<GroupTransport>,
        lock_id: LockId,
        cfg: GroupLockConfig,
        store: Arc<dyn AcceptorStateStore>,
        initial: Option<T>,
    ) -> Result<Self, GroupLockError> {
        let engine =
            crate::sync::group::create::create_engine(transport, lock_id, cfg, store, initial)
                .await?;
        Ok(Self {
            engine,
            _pd: PhantomData,
        })
    }

    /// Acquires the lock, waiting in the group-wide FIFO queue. Bounded by
    /// `cfg.acquire_timeout()`.
    pub async fn lock(&self) -> Result<NetGroupMutexGuard<T>, GroupLockError> {
        self.lock_with_timeout(self.engine.cfg.acquire_timeout())
            .await
    }

    /// Acquires with an explicit deadline.
    pub async fn lock_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<NetGroupMutexGuard<T>, GroupLockError> {
        let grant = self.engine.acquire(LockKind::Write, false, timeout).await?;
        NetGroupWriteGuard::from_grant(self.engine.clone(), grant)
    }

    /// Single-round attempt: `Ok(None)` if the lock is currently contended.
    pub async fn try_lock(&self) -> Result<Option<NetGroupMutexGuard<T>>, GroupLockError> {
        match self
            .engine
            .acquire(LockKind::Write, true, self.engine.cfg.round_timeout())
            .await
        {
            Ok(grant) => Ok(Some(NetGroupWriteGuard::from_grant(
                self.engine.clone(),
                grant,
            )?)),
            Err(GroupLockError::WouldBlock) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl<T: NetObject> Drop for NetGroupMutex<T> {
    fn drop(&mut self) {
        self.engine.shutdown();
    }
}
