//! Layer-3 integration tests: full stack over the in-memory mesh (n = 3 and 5),
//! exercising contention, value propagation, reader batching, writer priority,
//! downgrade, and try_* semantics.

use crate::sync::group::acceptor::EphemeralAcceptorStore;
use crate::sync::group::test_mesh::TestMesh;
use crate::sync::group::{GroupLockConfig, LockId, MemberId, NetGroupMutex, NetGroupRwLock};
use citadel_io::tokio;
use futures::future::join_all;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn members(n: u64) -> Vec<MemberId> {
    (1..=n).map(MemberId).collect()
}

pub(crate) fn test_config(all: &[MemberId], local: MemberId) -> GroupLockConfig {
    GroupLockConfig::new(
        all.to_vec(),
        local,
        all[0],                     // lowest member id owns the initial value
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

pub(crate) async fn create_mutexes<T: crate::sync::primitives::NetObject>(
    mesh: &TestMesh,
    all: &[MemberId],
    lock: LockId,
    initial: T,
) -> Vec<NetGroupMutex<T>> {
    let futures = all.iter().map(|m| {
        let cfg = test_config(all, *m);
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

#[tokio::test(flavor = "multi_thread")]
async fn mutex_contended_counter_n3() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("counter"), 0).await;

    const PER_MEMBER: u64 = 20;
    let in_cs = Arc::new(AtomicBool::new(false));
    let max_fence_seen = Arc::new(AtomicU64::new(0));

    let tasks = mutexes.into_iter().map(|mutex| {
        let in_cs = in_cs.clone();
        let max_fence_seen = max_fence_seen.clone();
        tokio::spawn(async move {
            for _ in 0..PER_MEMBER {
                let mut guard = mutex.lock().await.unwrap();
                // mutual exclusion: nobody else is in the critical section
                assert!(!in_cs.swap(true, Ordering::SeqCst), "two holders at once!");
                assert!(guard.recovered().is_none());
                // fences strictly increase across grants
                let prev = max_fence_seen.swap(guard.fence().0, Ordering::SeqCst);
                assert!(guard.fence().0 > prev, "fence went backwards");
                *guard += 1;
                assert!(in_cs.swap(false, Ordering::SeqCst), "cs flag desynced");
                guard.release().await.unwrap();
            }
            mutex
        })
    });
    let mutexes: Vec<_> = join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let final_guard = mutexes[0].lock().await.unwrap();
    assert_eq!(*final_guard, 3 * PER_MEMBER);
}

#[tokio::test(flavor = "multi_thread")]
async fn mutex_drop_propagates_value_n5() {
    citadel_logging::setup_log();
    let all = members(5);
    let mesh = TestMesh::new(&all);
    let mutexes =
        create_mutexes::<Vec<u32>>(&mesh, &all, LockId::from_name("payload"), vec![]).await;

    {
        let mut guard = mutexes[2].lock().await.unwrap();
        guard.push(1234);
        // drop (not explicit release) must still propagate the mutated value
    }
    // another member observes the committed value
    let guard = mutexes[4].lock().await.unwrap();
    assert_eq!(&*guard, &vec![1234]);
    assert!(guard.value_version().0 > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn rwlock_readers_batch_and_writers_have_priority_n3() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let rwlocks = create_rwlocks::<u64>(&mesh, &all, LockId::from_name("rw"), 7).await;

    // all three members hold read locks CONCURRENTLY
    let concurrent = Arc::new(AtomicU64::new(0));
    let peak = Arc::new(AtomicU64::new(0));
    let tasks = rwlocks.iter().map(|rw| {
        let concurrent = concurrent.clone();
        let peak = peak.clone();
        async move {
            let guard = rw.read().await.unwrap();
            assert_eq!(*guard, 7);
            let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            citadel_io::time::sleep(Duration::from_millis(300)).await;
            concurrent.fetch_sub(1, Ordering::SeqCst);
            guard.release().await.unwrap();
        }
    });
    join_all(tasks).await;
    assert_eq!(
        peak.load(Ordering::SeqCst),
        3,
        "readers must overlap (batching)"
    );

    // writer excludes readers; a write commits and is visible everywhere
    let mut w = rwlocks[1].write().await.unwrap();
    *w = 99;
    w.release().await.unwrap();
    let r = rwlocks[2].read().await.unwrap();
    assert_eq!(*r, 99);
}

#[tokio::test(flavor = "multi_thread")]
async fn rwlock_downgrade_lets_readers_join() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let rwlocks = create_rwlocks::<u64>(&mesh, &all, LockId::from_name("dg"), 0).await;

    let mut w = rwlocks[0].write().await.unwrap();
    *w = 5;
    let r0 = w.downgrade().await.unwrap();
    assert_eq!(*r0, 5, "downgraded guard sees its own write");

    // another member's reader joins while the downgraded read guard is held
    let r1 = rwlocks[1].read().await.unwrap();
    assert_eq!(*r1, 5);
    drop(r1);
    drop(r0);
}

#[tokio::test(flavor = "multi_thread")]
async fn try_lock_semantics() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("try"), 0).await;

    let guard = mutexes[0].lock().await.unwrap();
    assert!(
        mutexes[1].try_lock().await.unwrap().is_none(),
        "try_lock must not block or enqueue"
    );
    guard.release().await.unwrap();
    let g2 = mutexes[1].try_lock().await.unwrap();
    assert!(g2.is_some(), "free lock must be try-lockable");
}

#[tokio::test(flavor = "multi_thread")]
async fn unmutated_write_release_keeps_value() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("clean"), 41).await;

    let guard = mutexes[1].lock().await.unwrap();
    let version_before = guard.value_version();
    guard.release().await.unwrap(); // never mutated: no value shipped

    let guard = mutexes[2].lock().await.unwrap();
    assert_eq!(*guard, 41);
    assert_eq!(
        guard.value_version(),
        version_before,
        "unmutated release must not advance the value version"
    );
}
