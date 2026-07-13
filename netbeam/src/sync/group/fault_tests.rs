//! Layer-4 fault-injection tests: crashed holders (recovered flag + bounded
//! handoff), partitions (minority stalls + self-invalidates, majority steals,
//! stale release fenced after heal), and quorum-loss behavior at n = 2.

use crate::sync::group::acceptor::EphemeralAcceptorStore;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::integration_tests::{create_mutexes, members};
use crate::sync::group::test_mesh::TestMesh;
use crate::sync::group::{LockId, NetGroupMutex};
use citadel_io::tokio;
use std::sync::Arc;
use std::time::Duration;

/// An isolated holder cannot renew: its entry stagnates, a waiter steals, and the
/// next write grant reports `recovered` with the crashed member's identity — while
/// the crashed holder's uncommitted mutation stays invisible.
#[tokio::test(flavor = "multi_thread")]
async fn killed_holder_is_stolen_with_recovery_flag() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("crash"), 100).await;

    let mut dying_guard = mutexes[0].lock().await.unwrap();
    *dying_guard = 666; // uncommitted mutation: must never become visible
    let dying_fence = dying_guard.fence();
    mesh.isolate(all[0]); // "crash" the holder mid-critical-section

    let start = std::time::Instant::now();
    let guard = mutexes[1].lock().await.unwrap();
    // bounded handoff: lease + grace + rounds, with slack for test scheduling
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "steal took too long: {:?}",
        start.elapsed()
    );
    let recovered = guard.recovered().expect("must report writer crash");
    assert_eq!(recovered.member, all[0]);
    assert_eq!(recovered.fence, dying_fence);
    assert_eq!(*guard, 100, "uncommitted mutation must be invisible");
    assert!(guard.fence() > dying_fence, "fences stay monotonic");

    // the isolated holder learns it lost the grant
    dying_guard.invalidated().await;
    assert!(!dying_guard.is_valid());
    assert!(matches!(
        dying_guard.release().await,
        Err(GroupLockError::Stolen { .. }) | Err(GroupLockError::QuorumUnavailable)
    ));
}

/// Partition a 5-mesh 2/3: the majority side steals and proceeds; after healing,
/// the stale holder's explicit release is fenced out with `Stolen`.
#[tokio::test(flavor = "multi_thread")]
async fn partition_majority_steals_minority_fenced_after_heal() {
    citadel_logging::setup_log();
    let all = members(5);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("split"), 1).await;

    let mut stale_guard = mutexes[0].lock().await.unwrap();
    *stale_guard = 2; // will never commit
                      // {1,2} vs {3,4,5}
    mesh.partition(&all[..2], &all[2..]);

    // majority side acquires (steals the stagnant holder)
    let guard = mutexes[3].lock().await.unwrap();
    assert!(guard.recovered().is_some());
    assert_eq!(*guard, 1, "minority mutation must not be visible");
    guard.release().await.unwrap();

    // minority holder self-invalidates (cannot renew against a majority)
    stale_guard.invalidated().await;
    assert!(!stale_guard.is_valid());

    mesh.heal_all();
    // stale release after heal must be fenced, and must NOT overwrite the value
    assert!(matches!(
        stale_guard.release().await,
        Err(GroupLockError::Stolen { .. })
    ));
    let check = mutexes[4].lock().await.unwrap();
    assert_eq!(*check, 1);
}

/// With f = 2 of n = 5 voters isolated, the group stays fully live.
#[tokio::test(flavor = "multi_thread")]
async fn survives_f_minority_voter_crashes_n5() {
    citadel_logging::setup_log();
    let all = members(5);
    let mesh = TestMesh::new(&all);
    let mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("f2"), 0).await;

    mesh.isolate(all[3]);
    mesh.isolate(all[4]);

    for round in 0..3u64 {
        let mut guard = mutexes[(round % 3) as usize].lock().await.unwrap();
        *guard += 1;
        guard.release().await.unwrap();
    }
    let guard = mutexes[0].lock().await.unwrap();
    assert_eq!(*guard, 3);
}

/// n = 2 has majority 2: losing the peer makes acquisition fail (bounded), never
/// silently succeed — the documented degenerate case.
#[tokio::test(flavor = "multi_thread")]
async fn n2_quorum_loss_fails_bounded() {
    citadel_logging::setup_log();
    let all = members(2);
    let mesh = TestMesh::new(&all);
    // shorter acquire timeout to keep the test fast
    let futures = all.iter().map(|m| {
        let mut cfg_all = all.clone();
        cfg_all.sort_unstable();
        let cfg = crate::sync::group::GroupLockConfig::new(
            cfg_all,
            *m,
            all[0],
            Duration::from_millis(600),
            Duration::from_millis(150),
            Duration::from_millis(250),
            Duration::from_secs(2),
            Duration::from_millis(300),
            Duration::from_millis(25),
            Duration::from_millis(75),
        )
        .unwrap();
        let init = (*m == all[0]).then_some(5u64);
        NetGroupMutex::<u64>::create(
            mesh.transport(*m),
            LockId::from_name("n2"),
            cfg,
            Arc::new(EphemeralAcceptorStore::default()),
            init,
        )
    });
    let mutexes: Vec<_> = futures::future::join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    mesh.isolate(all[1]);
    let start = std::time::Instant::now();
    let result = mutexes[0].lock().await;
    assert!(
        matches!(
            result,
            Err(GroupLockError::QuorumUnavailable) | Err(GroupLockError::Timeout)
        ),
        "acquire must fail without a majority, got ok={}",
        result.is_ok()
    );
    assert!(start.elapsed() < Duration::from_secs(10));

    // heal: the group works again
    mesh.rejoin(all[1]);
    let mut guard = mutexes[1].lock().await.unwrap();
    *guard += 1;
    guard.release().await.unwrap();
    let guard = mutexes[0].lock().await.unwrap();
    assert_eq!(*guard, 6);
}

/// A waiter that dies in the queue is evicted by whoever it blocks; the queue
/// does not wedge behind a ghost entry.
#[tokio::test(flavor = "multi_thread")]
async fn dead_waiter_is_evicted() {
    citadel_logging::setup_log();
    let all = members(3);
    let mesh = TestMesh::new(&all);
    let mut mutexes = create_mutexes::<u64>(&mesh, &all, LockId::from_name("ghost"), 0).await;

    let guard = mutexes[0].lock().await.unwrap();

    // member 2 queues, then "crashes" while waiting
    let m1 = mutexes.remove(1);
    let waiter = tokio::spawn(async move {
        let _ = m1.lock().await; // never granted: isolated below
        m1
    });
    citadel_io::time::sleep(Duration::from_millis(300)).await; // let it enqueue
    mesh.isolate(all[1]);

    guard.release().await.unwrap();

    // member 3 queued behind the ghost must still make progress (janitor evicts it)
    let start = std::time::Instant::now();
    let mut g = mutexes[1].lock().await.unwrap(); // mutexes[1] is member 3 now
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "eviction took too long: {:?}",
        start.elapsed()
    );
    assert!(g.recovered().is_none(), "a stolen WAITER must not poison");
    *g += 1;
    g.release().await.unwrap();
    waiter.abort();
}
