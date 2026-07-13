//! Guard types shared by [`crate::sync::group::mutex`] and
//! [`crate::sync::group::rwlock`].
//!
//! A guard cannot physically revoke `&mut T` after its lease is lost: local code may
//! keep using its in-memory copy, but netbeam-managed state stays safe (a stale
//! holder's release CAS is fenced out). For EXTERNAL side effects, callers must check
//! [`NetGroupWriteGuard::is_valid`]/[`NetGroupWriteGuard::fence`] and pass the fence
//! to downstream systems.

use crate::sync::group::acquire::Grant;
use crate::sync::group::engine::Engine;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::grant_state::GrantState;
use crate::sync::group::record::PoisonInfo;
use crate::sync::group::Fence;
use crate::sync::primitives::NetObject;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Exclusive guard. Mutating access (`DerefMut`) marks the value dirty; only dirty
/// values are shipped on release.
pub struct NetGroupWriteGuard<T: NetObject> {
    pub(crate) value: Option<T>,
    pub(crate) mutated: bool,
    pub(crate) recovered: Option<PoisonInfo>,
    pub(crate) value_version: Fence,
    pub(crate) state: Arc<GrantState>,
}

/// Shared guard (read-only view of the value).
pub struct NetGroupReadGuard<T: NetObject> {
    pub(crate) value: T,
    pub(crate) value_version: Fence,
    pub(crate) state: Arc<GrantState>,
}

impl<T: NetObject> NetGroupWriteGuard<T> {
    pub(crate) fn from_grant(engine: Arc<Engine>, grant: Grant) -> Result<Self, GroupLockError> {
        let value = match bincode::deserialize::<T>(&grant.value) {
            Ok(v) => v,
            Err(err) => {
                // the grant IS committed: withdraw it (poison-free — the critical
                // section provably never ran) instead of orphaning it
                engine.spawn_best_effort_dequeue(grant.nonce);
                return Err(err.into());
            }
        };
        Ok(Self {
            value: Some(value),
            mutated: false,
            recovered: grant.recovered.clone(),
            value_version: grant.value_version,
            state: GrantState::new(engine, &grant),
        })
    }

    /// The fencing token of this grant — pass it to external systems so they can
    /// reject operations from stale holders.
    pub fn fence(&self) -> Fence {
        self.state.fence
    }

    /// Version (fence) of the value snapshot this guard started from.
    pub fn value_version(&self) -> Fence {
        self.value_version
    }

    /// `false` once the lease lapsed locally or the grant was observed stolen.
    pub fn is_valid(&self) -> bool {
        self.state.is_valid()
    }

    /// Resolves when the grant is invalidated (stolen or lease lost). Useful to
    /// abort long critical sections early.
    pub async fn invalidated(&self) {
        self.state.invalidated().await
    }

    /// `Some` iff the previous writer crashed mid-critical-section and this grant
    /// recovered the lock ("poisoned" semantics): the value is the last COMMITTED
    /// snapshot; the crashed holder's uncommitted mutations were discarded.
    pub fn recovered(&self) -> Option<&PoisonInfo> {
        self.recovered.as_ref()
    }

    /// Releases explicitly, surfacing errors the `Drop` path can only log.
    pub async fn release(mut self) -> Result<(), GroupLockError> {
        let new_value = self.take_release_payload()?;
        self.state.release(new_value).await
    }

    /// Converts a write guard into a read guard atomically (fresh fence; publishes
    /// the value if mutated). No `upgrade` exists: two readers upgrading deadlock.
    pub async fn downgrade(mut self) -> Result<NetGroupReadGuard<T>, GroupLockError> {
        let new_value = self.take_release_payload()?;
        let grant = self.state.downgrade(new_value).await?;
        NetGroupReadGuard::from_grant(self.state.engine.clone(), grant)
    }

    fn take_release_payload(&mut self) -> Result<Option<Vec<u8>>, GroupLockError> {
        let value = self.value.take();
        if !self.mutated {
            return Ok(None);
        }
        self.mutated = false; // the Drop that follows an explicit release is a no-op
        let value = value
            .ok_or_else(|| GroupLockError::Io("write guard value already taken".to_string()))?;
        Ok(Some(bincode::serialize(&value)?))
    }
}

impl<T: NetObject> NetGroupReadGuard<T> {
    pub(crate) fn from_grant(engine: Arc<Engine>, grant: Grant) -> Result<Self, GroupLockError> {
        let value = match bincode::deserialize::<T>(&grant.value) {
            Ok(v) => v,
            Err(err) => {
                engine.spawn_best_effort_dequeue(grant.nonce);
                return Err(err.into());
            }
        };
        Ok(Self {
            value,
            value_version: grant.value_version,
            state: GrantState::new(engine, &grant),
        })
    }

    pub fn fence(&self) -> Fence {
        self.state.fence
    }

    pub fn value_version(&self) -> Fence {
        self.value_version
    }

    pub fn is_valid(&self) -> bool {
        self.state.is_valid()
    }

    pub async fn invalidated(&self) {
        self.state.invalidated().await
    }

    pub async fn release(self) -> Result<(), GroupLockError> {
        self.state.release(None).await
    }
}

impl<T: NetObject> Deref for NetGroupWriteGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("value present until release")
    }
}

impl<T: NetObject> DerefMut for NetGroupWriteGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.mutated = true;
        self.value.as_mut().expect("value present until release")
    }
}

impl<T: NetObject> Deref for NetGroupReadGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: NetObject> Drop for NetGroupWriteGuard<T> {
    fn drop(&mut self) {
        match self.take_release_payload() {
            Ok(payload) => self.state.clone().spawn_release(payload),
            Err(err) => {
                log::warn!(target: "citadel", "[GroupLock] failed to serialize value on drop; releasing without it: {err}");
                self.state.clone().spawn_release(None);
            }
        }
    }
}

impl<T: NetObject> Drop for NetGroupReadGuard<T> {
    fn drop(&mut self) {
        self.state.clone().spawn_release(None);
    }
}
