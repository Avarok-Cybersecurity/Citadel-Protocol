//! Full-group-restart recovery: every member persists its voter state via
//! `SnapshotAcceptorStore`, the whole group (mesh + facades) is torn down, and the
//! members come back from bytes — the last committed value must survive, and a lone
//! returning member must be able to peek it offline before any quorum forms.

use crate::sync::group::persist::{peek_value, SnapshotAcceptorStore};
use crate::sync::group::test_mesh::TestMesh;
use crate::sync::group::test_util::{members, test_config};
use crate::sync::group::{LockId, MemberId, NetGroupMutex};
use citadel_io::tokio;
use futures::future::join_all;
use std::sync::Arc;

async fn create_all(
    mesh: &TestMesh,
    all: &[MemberId],
    lock: LockId,
    stores: &[Arc<SnapshotAcceptorStore>],
) -> Vec<NetGroupMutex<u64>> {
    let futures = all.iter().zip(stores).map(|(m, store)| {
        let cfg = test_config(all, *m);
        let init = (*m == all[0]).then_some(100u64);
        NetGroupMutex::<u64>::create(mesh.transport(*m), lock, cfg, store.clone(), init)
    });
    join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_group_restart_recovers_last_committed_value() {
    citadel_logging::setup_log();
    let all = members(3);
    let lock = LockId::from_name("persist");

    // ---- first incarnation: commit a value, then export every member's state ----
    let exported: Vec<Vec<u8>> = {
        let mesh = TestMesh::new(&all);
        let stores: Vec<_> = (0..3)
            .map(|_| Arc::new(SnapshotAcceptorStore::new()))
            .collect();
        let mutexes = create_all(&mesh, &all, lock, &stores).await;

        let mut guard = mutexes[1].lock().await.unwrap();
        *guard = 777;
        guard.release().await.unwrap(); // committed on a majority
        drop(mutexes); // graceful shutdown: engines unregister
        stores.iter().map(|s| s.to_bytes().unwrap()).collect()
        // mesh, transports, stores all drop here — "all users drop"
    };

    // ---- a lone returning member reads its last known value offline ----
    let lone = SnapshotAcceptorStore::from_bytes(&exported[1]).unwrap();
    let (version, value) = peek_value::<u64>(&lone, lock).unwrap().unwrap();
    assert_eq!(
        value, 777,
        "lone member must see the committed value offline"
    );
    assert!(version.0 > 0);

    // ---- full restart from bytes: the group resumes with the committed value ----
    let mesh = TestMesh::new(&all);
    let stores: Vec<_> = exported
        .iter()
        .map(|b| Arc::new(SnapshotAcceptorStore::from_bytes(b).unwrap()))
        .collect();
    // the owner passes Some(initial) again; Init is denied AlreadyInitialized and
    // treated as success — the restored record wins, never the re-supplied initial
    let mutexes = create_all(&mesh, &all, lock, &stores).await;

    let mut guard = mutexes[2].lock().await.unwrap();
    assert_eq!(
        *guard, 777,
        "restart must resume from the last committed value, not the initial"
    );
    // and the group is fully operational: mutate + hand off across members
    *guard += 1;
    guard.release().await.unwrap();
    let guard = mutexes[0].lock().await.unwrap();
    assert_eq!(*guard, 778);
}

/// Restoring only a MAJORITY (2 of 3) must also recover the committed value —
/// the quorum-intersection guarantee, exercised through real engines.
#[tokio::test(flavor = "multi_thread")]
async fn majority_restart_recovers_value_without_third_member() {
    citadel_logging::setup_log();
    let all = members(3);
    let lock = LockId::from_name("persist-majority");

    let exported: Vec<Vec<u8>> = {
        let mesh = TestMesh::new(&all);
        let stores: Vec<_> = (0..3)
            .map(|_| Arc::new(SnapshotAcceptorStore::new()))
            .collect();
        let mutexes = create_all(&mesh, &all, lock, &stores).await;
        let mut guard = mutexes[0].lock().await.unwrap();
        *guard = 555;
        guard.release().await.unwrap();
        drop(mutexes);
        stores.iter().map(|s| s.to_bytes().unwrap()).collect()
    };

    // only members 1 and 2 return; member 3 stays gone (isolated from creation)
    let mesh = TestMesh::new(&all);
    mesh.isolate(all[2]);
    let stores: Vec<_> = exported[..2]
        .iter()
        .map(|b| Arc::new(SnapshotAcceptorStore::from_bytes(b).unwrap()))
        .collect();
    let futures = all[..2].iter().zip(&stores).map(|(m, store)| {
        let cfg = test_config(&all, *m);
        let init = (*m == all[0]).then_some(100u64);
        NetGroupMutex::<u64>::create(mesh.transport(*m), lock, cfg, store.clone(), init)
    });
    let mutexes: Vec<_> = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let guard = mutexes[1].lock().await.unwrap();
    assert_eq!(*guard, 555, "any majority must recover the committed value");
}
