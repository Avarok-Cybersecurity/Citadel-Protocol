//! N-node fault-tolerant read-write lock with tokio-style write-preferring FIFO
//! semantics: readers are admitted in concurrent batches between writers; once a
//! writer queues, later readers wait behind it (no writer starvation). There is no
//! read→write upgrade (two upgrading readers deadlock by construction); write→read
//! [`NetGroupWriteGuard::downgrade`] is supported.

use crate::sync::group::acceptor::AcceptorStateStore;
use crate::sync::group::config::GroupLockConfig;
use crate::sync::group::engine::Engine;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::guard::{NetGroupReadGuard, NetGroupWriteGuard};
use crate::sync::group::transport::GroupTransport;
use crate::sync::group::{LockId, LockKind};
use crate::sync::primitives::NetObject;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

pub struct NetGroupRwLock<T: NetObject> {
    engine: Arc<Engine>,
    _pd: PhantomData<fn() -> T>,
}

impl<T: NetObject> NetGroupRwLock<T> {
    /// Joins (and on the owner, initializes) the distributed rwlock `lock_id`.
    /// Every member must call this; exactly the `initial_value_owner` passes `Some`.
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

    /// Shared access; batches with concurrent readers group-wide.
    pub async fn read(&self) -> Result<NetGroupReadGuard<T>, GroupLockError> {
        self.read_with_timeout(self.engine.cfg.acquire_timeout())
            .await
    }

    pub async fn read_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<NetGroupReadGuard<T>, GroupLockError> {
        let grant = self.engine.acquire(LockKind::Read, false, timeout).await?;
        NetGroupReadGuard::from_grant(self.engine.clone(), grant)
    }

    /// Exclusive access.
    pub async fn write(&self) -> Result<NetGroupWriteGuard<T>, GroupLockError> {
        self.write_with_timeout(self.engine.cfg.acquire_timeout())
            .await
    }

    pub async fn write_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<NetGroupWriteGuard<T>, GroupLockError> {
        let grant = self.engine.acquire(LockKind::Write, false, timeout).await?;
        NetGroupWriteGuard::from_grant(self.engine.clone(), grant)
    }

    /// Single-round attempts: `Ok(None)` when contended.
    pub async fn try_read(&self) -> Result<Option<NetGroupReadGuard<T>>, GroupLockError> {
        match self
            .engine
            .acquire(LockKind::Read, true, self.engine.cfg.round_timeout())
            .await
        {
            Ok(grant) => Ok(Some(NetGroupReadGuard::from_grant(
                self.engine.clone(),
                grant,
            )?)),
            Err(GroupLockError::WouldBlock) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn try_write(&self) -> Result<Option<NetGroupWriteGuard<T>>, GroupLockError> {
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

impl<T: NetObject> Drop for NetGroupRwLock<T> {
    fn drop(&mut self) {
        self.engine.shutdown();
    }
}
