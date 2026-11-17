//! Deleting an account removes it from its peers for good: after a restart over the same store,
//! no surviving peer lists it, and nothing it stored remains.
#[path = "common/server_accounts.rs"]
mod server_accounts;

use citadel_io::tokio;
use citadel_user::backend::BackendType;
use server_accounts::{cheap_argon, file_backend, fresh_dir, manager, register};

#[tokio::test]
async fn a_deleted_account_is_gone_from_its_peers_after_a_restart() {
    let dir = fresh_dir("deleted_account_peers");
    let backend = file_backend(&dir);
    let mgr = manager(backend.clone(), cheap_argon()).await;
    let (a, _) = register(&mgr, "deleted_peer_a", "password123").await;
    let (b, _) = register(&mgr, "deleted_peer_b", "password123").await;
    mgr.register_hyperlan_p2p_as_server(a, b).await.unwrap();
    mgr.delete_client_by_cid(a).await.unwrap();
    let before_restart = mgr
        .get_hyperlan_peer_list(b)
        .await
        .unwrap()
        .unwrap_or_default();
    assert!(
        !before_restart.contains(&a),
        "the live view still lists the deleted peer"
    );
    drop(mgr);

    let reloaded = manager(backend, cheap_argon()).await;
    assert!(!reloaded.hyperlan_cid_is_registered(a).await.unwrap());
    let after_restart = reloaded
        .get_hyperlan_peer_list(b)
        .await
        .unwrap()
        .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !after_restart.contains(&a),
        "after a restart, B still lists deleted account {a} as a peer: {after_restart:?}"
    );
}

#[tokio::test]
async fn a_deleted_accounts_virtual_filesystem_is_removed() {
    let dir = fresh_dir("deleted_account_revfs");
    let mgr = manager(file_backend(&dir), cheap_argon()).await;
    let (a, _) = register(&mgr, "deleted_revfs_a", "password123").await;
    let (b, _) = register(&mgr, "deleted_revfs_b", "password123").await;
    let owned = |cid: u64| dir.join("virtual").join(cid.to_string());
    for cid in [a, b] {
        std::fs::create_dir_all(owned(cid).join("docs")).unwrap();
        std::fs::write(owned(cid).join("docs").join("note.bin"), b"stored").unwrap();
    }

    mgr.delete_client_by_cid(a).await.unwrap();
    let a_left = owned(a).exists();
    let b_kept = owned(b).join("docs").join("note.bin").exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !a_left,
        "the deleted account's virtual filesystem is still on disk"
    );
    assert!(b_kept, "deleting one account removed another's files");
}

#[tokio::test]
async fn values_stored_about_a_deleted_account_are_dropped() {
    let mgr = manager(BackendType::InMemory, cheap_argon()).await;
    let (a, _) = register(&mgr, "deleted_bytes_a", "password123").await;
    let (b, _) = register(&mgr, "deleted_bytes_b", "password123").await;
    mgr.register_hyperlan_p2p_as_server(a, b).await.unwrap();
    let handler = mgr.get_persistence_handler();
    let _ = handler
        .store_byte_map_value(b, a, "key", "sub", b"about a".to_vec())
        .await
        .unwrap();

    mgr.delete_client_by_cid(a).await.unwrap();
    let left = handler
        .get_byte_map_value(b, a, "key", "sub")
        .await
        .unwrap();
    assert_eq!(
        left, None,
        "B still holds a value stored about deleted account {a}"
    );
}
