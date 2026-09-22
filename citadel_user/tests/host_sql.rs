//! The host_sql backend's own regressions: the three duplicate-row defects the SQL backend
//! shipped with (#305, #306, #307), which this backend's primary keys must rule out, and the
//! host's failures reaching the caller.

#[path = "common/sqlite_host.rs"]
mod sqlite_host;

use async_trait::async_trait;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::backend::host_sql::{
    HostSqlBackend, HostSqlHandle, SqlHost, SqlRow, SqlStatement, SqlValue,
};
use citadel_user::backend::BackendConnection;
use sqlite_host::SqliteHost;

type Backend = HostSqlBackend<StackedRatchet, StackedRatchet>;

async fn connected(host: &HostSqlHandle) -> Backend {
    let mut backend = Backend::new(host.clone());
    BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend)
        .await
        .unwrap();
    backend
}

async fn sql(host: &HostSqlHandle, sql: &'static str, params: Vec<SqlValue>) -> Vec<SqlRow> {
    host.0
        .execute(vec![SqlStatement { sql, params }])
        .await
        .unwrap()
        .remove(0)
}

/// An account row with no real CNAC behind it: these tests are about pairs and byte maps.
async fn seed_account(host: &HostSqlHandle, cid: u64, username: &str) {
    let _ = sql(
        host,
        "INSERT INTO citadel_cnacs (cid, is_personal, username, full_name, creation_date, bin) VALUES (?, 0, ?, '', '', x'')",
        vec![SqlValue::Text(cid.to_string()), SqlValue::Text(username.into())],
    )
    .await;
}

async fn count(host: &HostSqlHandle, sql_text: &'static str, params: Vec<SqlValue>) -> i64 {
    match sql(host, sql_text, params).await[0][0] {
        SqlValue::Integer(n) => n,
        ref other => panic!("count was {other:?}"),
    }
}

#[tokio::test]
async fn storing_twice_overwrites_rather_than_appending() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let (cid, peer) = (777u64, 0u64);

    let first = backend
        .store_byte_map_value(cid, peer, "k", "sub", b"first".to_vec())
        .await
        .unwrap();
    let previous = backend
        .store_byte_map_value(cid, peer, "k", "sub", b"second".to_vec())
        .await
        .unwrap();
    let got = backend
        .get_byte_map_value(cid, peer, "k", "sub")
        .await
        .unwrap();
    let rows = count(
        &host,
        "SELECT COUNT(*) FROM citadel_bytemap WHERE cid = ? AND id = 'k' AND sub_id = 'sub'",
        vec![SqlValue::Text(cid.to_string())],
    )
    .await;

    assert_eq!(first, None);
    assert_eq!(previous.as_deref(), Some(&b"first"[..]));
    assert_eq!(
        got.as_deref(),
        Some(&b"second"[..]),
        "the second store must be read back"
    );
    assert_eq!(
        rows, 1,
        "one key must hold exactly one row, not a row per write"
    );
}

#[tokio::test]
async fn a_pair_registered_twice_is_still_one_registered_pair() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let (me, twice, once) = (101u64, 202u64, 303u64);
    for (cid, name) in [(me, "me"), (twice, "twice"), (once, "once")] {
        seed_account(&host, cid, name).await;
    }

    backend.register_p2p_as_server(me, twice).await.unwrap();
    backend.register_p2p_as_server(me, twice).await.unwrap();
    backend.register_p2p_as_server(me, once).await.unwrap();

    assert!(backend.hyperlan_peer_exists(me, twice).await.unwrap());
    assert!(backend.hyperlan_peer_exists(twice, me).await.unwrap());
    let list = backend.get_hyperlan_peer_list(me).await.unwrap().unwrap();
    assert_eq!(list, vec![twice, once], "the peer list repeated a peer");
    assert_eq!(
        backend
            .hyperlan_peers_are_mutuals(me, &[twice, once])
            .await
            .unwrap(),
        vec![true, true]
    );
    let mutual: Vec<(u64, Option<String>)> = backend
        .get_hyperlan_peers(me, &[twice, once])
        .await
        .unwrap()
        .into_iter()
        .map(|p| (p.cid, p.username))
        .collect();
    assert_eq!(
        mutual,
        vec![(twice, Some("twice".into())), (once, Some("once".into()))]
    );
    let rows = count(&host, "SELECT COUNT(*) FROM citadel_peers", vec![]).await;
    assert_eq!(
        rows, 4,
        "two pairs are four directed rows, whatever was registered twice"
    );
}

#[tokio::test]
async fn a_pair_recorded_twice_is_gone_after_one_removal() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let (me, them) = (11u64, 22u64);
    seed_account(&host, me, "me").await;
    seed_account(&host, them, "them").await;

    backend.register_p2p_as_server(me, them).await.unwrap();
    backend.register_p2p_as_server(them, me).await.unwrap();
    backend.deregister_p2p_as_server(me, them).await.unwrap();
    assert!(!backend.hyperlan_peer_exists(me, them).await.unwrap());
    assert!(!backend.hyperlan_peer_exists(them, me).await.unwrap());

    backend
        .register_p2p_as_client(me, them, "them".into())
        .await
        .unwrap();
    backend
        .register_p2p_as_client(me, them, "them".into())
        .await
        .unwrap();
    let removed = backend.deregister_p2p_as_client(me, them).await.unwrap();
    assert_eq!(removed.map(|p| p.cid), Some(them));
    assert!(!backend.hyperlan_peer_exists(me, them).await.unwrap());
    assert_eq!(
        backend.deregister_p2p_as_client(me, them).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn deleting_an_account_removes_its_pairs_and_byte_map() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let (gone, stays) = (5u64, 6u64);
    seed_account(&host, gone, "gone").await;
    seed_account(&host, stays, "stays").await;
    backend.register_p2p_as_server(gone, stays).await.unwrap();
    let _ = backend
        .store_byte_map_value(gone, 0, "k", "s", b"v".to_vec())
        .await
        .unwrap();
    let _ = backend
        .store_byte_map_value(stays, 0, "k", "s", b"v".to_vec())
        .await
        .unwrap();

    backend.delete_cnac_by_cid(gone).await.unwrap();

    assert!(!backend.cid_is_registered(gone).await.unwrap());
    assert!(!backend.hyperlan_peer_exists(stays, gone).await.unwrap());
    assert_eq!(
        backend.get_byte_map_value(gone, 0, "k", "s").await.unwrap(),
        None
    );
    assert!(backend
        .get_byte_map_value(stays, 0, "k", "s")
        .await
        .unwrap()
        .is_some());
    assert!(
        backend.delete_cnac_by_cid(gone).await.is_err(),
        "a second delete must fail"
    );
}

#[tokio::test]
async fn pairing_with_an_unknown_account_is_refused_and_writes_nothing() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    seed_account(&host, 1, "known").await;
    assert!(backend.register_p2p_as_server(1, 999).await.is_err());
    assert!(backend
        .register_p2p_as_client(999, 1, "x".into())
        .await
        .is_err());
    assert_eq!(
        count(&host, "SELECT COUNT(*) FROM citadel_peers", vec![]).await,
        0
    );
}

struct FailingHost;

#[async_trait]
impl SqlHost for FailingHost {
    async fn execute(&self, _: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
        Err("storage unavailable".into())
    }
}

struct ShortHost;

#[async_trait]
impl SqlHost for ShortHost {
    async fn execute(&self, _: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn a_host_failure_reaches_the_caller() {
    let mut backend = Backend::new(HostSqlHandle::new(FailingHost));
    let connect = BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend).await;
    let err = connect.expect_err("connect over a failing host must fail");
    assert!(err.to_string().contains("storage unavailable"), "{err}");
    assert!(!backend.is_connected().await.unwrap());
    assert!(backend
        .store_byte_map_value(1, 0, "k", "s", vec![1])
        .await
        .is_err());
}

#[tokio::test]
async fn a_host_that_drops_results_is_an_error_not_an_empty_answer() {
    let backend = Backend::new(HostSqlHandle::new(ShortHost));
    assert!(backend.get_byte_map_value(1, 0, "k", "s").await.is_err());
    assert!(backend.cid_is_registered(1).await.is_err());
}
