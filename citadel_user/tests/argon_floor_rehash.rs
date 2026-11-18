//! A legacy (Argon2) login against a stored hash made with parameters below the floor succeeds,
//! and replaces the hash with one under the node's settings when those meet the floor.
#[path = "common/server_accounts.rs"]
mod server_accounts;

use citadel_crypt::argon::argon_container::{
    ArgonContainerType, ArgonDefaultServerSettings, ArgonSettings, ARGON_FLOOR_LANES,
    ARGON_FLOOR_MEM_COST, ARGON_FLOOR_TIME_COST,
};
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::auth::DeclaredAuthenticationMode;
use server_accounts::{cheap_argon, file_backend, fresh_dir, manager, register, Manager};

const PASSWORD: &str = "a password";

/// Exactly the floor: the cheapest settings a node can use and still re-hash.
fn floor_argon() -> ArgonDefaultServerSettings {
    ArgonDefaultServerSettings {
        lanes: ARGON_FLOOR_LANES,
        hash_length: 32,
        mem_cost: ARGON_FLOOR_MEM_COST,
        time_cost: ARGON_FLOOR_TIME_COST,
        secret: vec![],
    }
}

async fn stored_settings(mgr: &Manager, cid: u64) -> ArgonSettings {
    let cnac = mgr.get_client_by_cid(cid).await.unwrap().unwrap();
    let store = cnac.auth_store();
    match &*store {
        DeclaredAuthenticationMode::Argon {
            argon: argon @ ArgonContainerType::Server(_),
            ..
        } => argon.settings().clone(),
        _ => panic!("not a server-side Argon2 account"),
    }
}

async fn login(mgr: &Manager, cid: u64, client: &ArgonSettings, password: &str) -> bool {
    let cnac = mgr.get_client_by_cid(cid).await.unwrap().unwrap();
    let creds = ProposedCredentials::new_connect(
        "Full Name",
        cnac.get_username(),
        SecBuffer::from(password),
        client.clone(),
    )
    .await
    .unwrap();
    mgr.verify_legacy_login(&cnac, creds).await.is_ok()
}

/// An account registered on a node whose settings are below the floor.
async fn weak_account(backend: citadel_user::backend::BackendType) -> (u64, ArgonSettings) {
    let mgr = manager(backend, cheap_argon()).await;
    let (cid, reg) = register(&mgr, "weak_hash_owner", PASSWORD).await;
    assert!(!stored_settings(&mgr, cid).await.meets_floor());
    (cid, reg.decompose().3.unwrap())
}

#[tokio::test]
async fn a_below_floor_hash_is_replaced_at_a_successful_login() {
    let dir = fresh_dir("argon_floor_rehash");
    let backend = file_backend(&dir);
    let (cid, client) = weak_account(backend.clone()).await;

    let mgr = manager(backend.clone(), floor_argon()).await;
    assert!(
        login(&mgr, cid, &client, PASSWORD).await,
        "the login itself was refused"
    );
    assert!(
        stored_settings(&mgr, cid).await.meets_floor(),
        "the below-floor hash was kept"
    );
    assert!(
        login(&mgr, cid, &client, PASSWORD).await,
        "the re-hashed account no longer logs in"
    );
    assert!(!login(&mgr, cid, &client, "another password").await);
    drop(mgr);

    // The replacement reached the store: a node that would not re-hash reads it back.
    let reloaded = manager(backend, cheap_argon()).await;
    let persisted = stored_settings(&reloaded, cid).await.meets_floor();
    let still_logs_in = login(&reloaded, cid, &client, PASSWORD).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(persisted, "the re-hash was not saved");
    assert!(still_logs_in);
}

#[tokio::test]
async fn a_wrong_password_leaves_a_below_floor_hash_alone() {
    let dir = fresh_dir("argon_floor_wrong_password");
    let backend = file_backend(&dir);
    let (cid, client) = weak_account(backend.clone()).await;

    let mgr = manager(backend, floor_argon()).await;
    assert!(!login(&mgr, cid, &client, "another password").await);
    let kept = !stored_settings(&mgr, cid).await.meets_floor();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(kept, "a refused login replaced the stored hash");
}

#[tokio::test]
async fn a_node_below_the_floor_keeps_what_is_stored() {
    let dir = fresh_dir("argon_floor_cheap_node");
    let backend = file_backend(&dir);
    let (cid, client) = weak_account(backend.clone()).await;

    let mgr = manager(backend, cheap_argon()).await;
    assert!(login(&mgr, cid, &client, PASSWORD).await);
    let kept = !stored_settings(&mgr, cid).await.meets_floor();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(kept);
}
