//! Shared helpers for the async test suites (integration/fault/persist): member
//! sets, lock-group config profiles, and mesh-wide lock constructors.
//!
//! Two config profiles exist deliberately:
//! - [`test_config`]: FUNCTIONAL profile. Lease timings are derived so that a
//!   spurious steal requires a multi-second stall of one task (`lease_duration +
//!   steal_grace` = 8s of observed stagnation), which no loaded CI runner produces
//!   without also blowing the acquire timeout. Functional tests must never see a
//!   legitimate `Stolen`.
//! - [`fast_steal_config`]: FAULT profile. Short lease so steal/evict paths run in
//!   bounded test time; tests using it EXPECT steals and assert on them.

use crate::sync::group::acceptor::EphemeralAcceptorStore;
use crate::sync::group::test_mesh::TestMesh;
use crate::sync::group::{GroupLockConfig, LockId, MemberId, NetGroupMutex, NetGroupRwLock};
use futures::future::join_all;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn members(n: u64) -> Vec<MemberId> {
    (1..=n).map(MemberId).collect()
}

/// Functional profile: steal window (lease + grace) = 8s on the observer's clock.
/// Renew every 1.5s keeps `renew_interval < lease_duration / 2` with margin while
/// minimizing heartbeat-proposal noise during contention tests.
pub(crate) fn test_config(all: &[MemberId], local: MemberId) -> GroupLockConfig {
    GroupLockConfig::new(
        all.to_vec(),
        local,
        all[0],                      // lowest member id owns the initial value
        Duration::from_secs(6),      // lease_duration
        Duration::from_millis(1500), // renew_interval
        Duration::from_secs(2),      // steal_grace
        Duration::from_secs(15),     // acquire_timeout
        Duration::from_millis(400),  // round_timeout
        Duration::from_millis(25),   // cas_backoff_base
        Duration::from_millis(75),   // waiter_poll_interval
    )
    .unwrap()
}

/// Fault profile: steal window (lease + grace) = 850ms, so crashed-holder steals
/// and dead-waiter evictions complete inside the tests' bounded-handoff asserts.
pub(crate) fn fast_steal_config(all: &[MemberId], local: MemberId) -> GroupLockConfig {
    GroupLockConfig::new(
        all.to_vec(),
        local,
        all[0],
        Duration::from_millis(600), // lease_duration
        Duration::from_millis(150), // renew_interval
        Duration::from_millis(250), // steal_grace
        Duration::from_secs(15),    // acquire_timeout
        Duration::from_millis(400), // round_timeout
        Duration::from_millis(25),  // cas_backoff_base
        Duration::from_millis(75),  // waiter_poll_interval
    )
    .unwrap()
}

pub(crate) type ConfigFn = fn(&[MemberId], MemberId) -> GroupLockConfig;

pub(crate) async fn create_mutexes_with<T: crate::sync::primitives::NetObject>(
    cfg_fn: ConfigFn,
    mesh: &TestMesh,
    all: &[MemberId],
    lock: LockId,
    initial: T,
) -> Vec<NetGroupMutex<T>> {
    let futures = all.iter().map(|m| {
        let cfg = cfg_fn(all, *m);
        let init = (*m == all[0]).then(|| initial.clone());
        NetGroupMutex::<T>::create(
            mesh.transport(*m),
            lock,
            cfg,
            Arc::new(EphemeralAcceptorStore::default()),
            init,
        )
    });
    join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub(crate) async fn create_mutexes<T: crate::sync::primitives::NetObject>(
    mesh: &TestMesh,
    all: &[MemberId],
    lock: LockId,
    initial: T,
) -> Vec<NetGroupMutex<T>> {
    create_mutexes_with(test_config, mesh, all, lock, initial).await
}

pub(crate) async fn create_rwlocks<T: crate::sync::primitives::NetObject>(
    mesh: &TestMesh,
    all: &[MemberId],
    lock: LockId,
    initial: T,
) -> Vec<NetGroupRwLock<T>> {
    let futures = all.iter().map(|m| {
        let cfg = test_config(all, *m);
        let init = (*m == all[0]).then(|| initial.clone());
        NetGroupRwLock::<T>::create(
            mesh.transport(*m),
            lock,
            cfg,
            Arc::new(EphemeralAcceptorStore::default()),
            init,
        )
    });
    join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
