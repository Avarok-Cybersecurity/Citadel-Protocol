//! WASM Integration Tests — In-Memory Backend
//!
//! Verifies that the AccountManager and in-memory backend work correctly
//! on the wasm32-unknown-unknown target.

#![cfg(target_family = "wasm")]

use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

/// Verify AccountManager can be created with InMemory backend on WASM.
#[wasm_bindgen_test]
async fn test_account_manager_in_memory() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    assert_eq!(manager.get_backend_type(), &BackendType::InMemory);
}

/// Verify AccountManager reports connected after initialization.
#[wasm_bindgen_test]
async fn test_account_manager_connected() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    let connected = manager.get_persistence_handler().is_connected().await;
    assert!(connected.is_ok());
    assert!(connected.unwrap());
}

/// Verify byte map store/get/remove operations work on WASM.
#[wasm_bindgen_test]
async fn test_byte_map_operations() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    let handler = manager.get_persistence_handler();
    // CID 0 is auto-registered by AccountManager::new via setup_local_only_account
    let cid = 0;
    let peer_cid = 0;

    // Store a value
    let prev = handler
        .store_byte_map_value(cid, peer_cid, "test_key", "sub_key", b"hello".to_vec())
        .await
        .expect("store failed");
    assert!(prev.is_none());

    // Retrieve the value
    let val = handler
        .get_byte_map_value(cid, peer_cid, "test_key", "sub_key")
        .await
        .expect("get failed");
    assert_eq!(val, Some(b"hello".to_vec()));

    // Overwrite the value
    let prev = handler
        .store_byte_map_value(cid, peer_cid, "test_key", "sub_key", b"world".to_vec())
        .await
        .expect("overwrite failed");
    assert_eq!(prev, Some(b"hello".to_vec()));

    // Remove the value
    let removed = handler
        .remove_byte_map_value(cid, peer_cid, "test_key", "sub_key")
        .await
        .expect("remove failed");
    assert_eq!(removed, Some(b"world".to_vec()));

    // Verify it's gone
    let gone = handler
        .get_byte_map_value(cid, peer_cid, "test_key", "sub_key")
        .await
        .expect("get-after-remove failed");
    assert!(gone.is_none());
}

/// Verify byte map bulk key operations work on WASM.
#[wasm_bindgen_test]
async fn test_byte_map_bulk_operations() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    let handler = manager.get_persistence_handler();
    // CID 0 is auto-registered by AccountManager::new via setup_local_only_account
    let cid = 0;
    let peer_cid = 0;

    // Store multiple sub-keys under the same key
    let _ = handler
        .store_byte_map_value(cid, peer_cid, "config", "timeout", b"30".to_vec())
        .await
        .unwrap();
    let _ = handler
        .store_byte_map_value(cid, peer_cid, "config", "retries", b"3".to_vec())
        .await
        .unwrap();
    let _ = handler
        .store_byte_map_value(cid, peer_cid, "config", "debug", b"true".to_vec())
        .await
        .unwrap();

    // Get all values by key
    let all = handler
        .get_byte_map_values_by_key(cid, peer_cid, "config")
        .await
        .expect("get_by_key failed");
    assert_eq!(all.len(), 3);
    assert_eq!(all.get("timeout"), Some(&b"30".to_vec()));
    assert_eq!(all.get("retries"), Some(&b"3".to_vec()));
    assert_eq!(all.get("debug"), Some(&b"true".to_vec()));

    // Remove all values by key
    let removed = handler
        .remove_byte_map_values_by_key(cid, peer_cid, "config")
        .await
        .expect("remove_by_key failed");
    assert_eq!(removed.len(), 3);

    // Verify empty
    let empty = handler
        .get_byte_map_values_by_key(cid, peer_cid, "config")
        .await
        .expect("verify empty failed");
    assert!(empty.is_empty());
}

/// Verify purge clears all data on WASM.
#[wasm_bindgen_test]
async fn test_purge() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    let count = manager
        .get_persistence_handler()
        .purge()
        .await
        .expect("purge failed");
    // AccountManager::new auto-registers CID 0 via setup_local_only_account
    assert_eq!(count, 1);
}

/// Verify CID lookup returns None for unregistered users on WASM.
#[wasm_bindgen_test]
async fn test_unregistered_user_lookup() {
    let manager = AccountManager::<StackedRatchet>::new(BackendType::InMemory, None, None, None)
        .await
        .expect("Failed to create AccountManager");

    let handler = manager.get_persistence_handler();

    let exists = handler
        .cid_is_registered(12345)
        .await
        .expect("lookup failed");
    assert!(!exists);

    let cnac = handler.get_cnac_by_cid(12345).await.expect("get failed");
    assert!(cnac.is_none());

    let name = handler
        .get_username_by_cid(12345)
        .await
        .expect("username lookup failed");
    assert!(name.is_none());
}
