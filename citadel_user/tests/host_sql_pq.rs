//! A post-quantum account record through the host_sql backend (the Durable Object's SQLite): it
//! survives the round trip byte for byte, and the account manager's changes to it (a sign-in, and
//! the migration hook it runs) reach the stored row, not only the copy in memory.

#[path = "common/sqlite_host.rs"]
mod sqlite_host;

use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::pq::client::ClientRegistration;
use citadel_user::auth::pq::oprf::OprfSeed;
use citadel_user::auth::pq::record::{KsfParams, PqAuthRecord};
use citadel_user::auth::pq::server::{registration_reply, PqAuthServerSettings};
use citadel_user::auth::{DeclaredAuthenticationMode, PqAuthSide};
use citadel_user::backend::host_sql::{HostSqlBackend, HostSqlHandle};
use citadel_user::backend::{BackendConnection, BackendType};
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::prelude::ConnectionInfo;
use citadel_user::server_misc_settings::ServerMiscSettings;
use sqlite_host::SqliteHost;

type Cnac = ClientNetworkAccount<StackedRatchet, StackedRatchet>;
type Manager = AccountManager<StackedRatchet, StackedRatchet>;

fn settings() -> PqAuthServerSettings {
    PqAuthServerSettings::new(OprfSeed::from_bytes([9u8; 32]), KsfParams::FLOOR).unwrap()
}

async fn record(username: &str) -> PqAuthRecord {
    let password = SecBuffer::from(b"pw-host-sql".to_vec());
    let (start, client) = ClientRegistration::start(username, &password).unwrap();
    let (reply, pending) = registration_reply(&settings(), &start).unwrap();
    let (finish, _) = client.finish(&reply, true).await.unwrap();
    pending.finish(finish, 5).unwrap()
}

async fn cnac(cid: u64, auth_store: DeclaredAuthenticationMode) -> Cnac {
    let info = ConnectionInfo {
        addr: "127.0.0.1:1".parse().unwrap(),
    };
    Cnac::new(cid, false, info, auth_store, None).await.unwrap()
}

async fn manager(host: &HostSqlHandle) -> Manager {
    let misc = ServerMiscSettings {
        pq_sign_in: Some(settings()),
        ..Default::default()
    };
    Manager::new(BackendType::HostSql(host.clone()), None, Some(misc))
        .await
        .unwrap()
}

/// A second backend over the same database: nothing it returns can come from the first one's
/// memory.
async fn reload(host: &HostSqlHandle, cid: u64) -> Cnac {
    let mut backend = HostSqlBackend::<StackedRatchet, StackedRatchet>::new(host.clone());
    BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend)
        .await
        .unwrap();
    backend.get_cnac_by_cid(cid).await.unwrap().expect("stored")
}

#[tokio::test]
async fn a_post_quantum_record_round_trips_through_host_sql() {
    let host = SqliteHost::handle();
    let manager = manager(&host).await;
    let record = record("alice").await;
    let account = cnac(
        4242,
        DeclaredAuthenticationMode::PostQuantum {
            username: "alice".into(),
            full_name: "Alice".into(),
            side: PqAuthSide::Server(Box::new(record.clone())),
        },
    )
    .await;
    manager
        .get_persistence_handler()
        .save_cnac(&account)
        .await
        .unwrap();

    let back = reload(&host, 4242).await;
    assert_eq!(back.auth_store().pq_record(), Some(&record));
    assert_eq!(back.get_username(), "alice");

    manager.record_pq_sign_in(4242, &[1, 2]).await.unwrap();
    let after = reload(&host, 4242).await;
    let stored = after.auth_store().pq_record().cloned().unwrap();
    assert!(stored.factor(1).unwrap().last_used_ms.is_some());
    assert!(
        stored.factor(2).unwrap().consumed,
        "the recovery code was not spent in the row"
    );
    assert!(
        manager.record_pq_sign_in(4242, &[2]).await.is_err(),
        "a spent code was spent again"
    );
}
