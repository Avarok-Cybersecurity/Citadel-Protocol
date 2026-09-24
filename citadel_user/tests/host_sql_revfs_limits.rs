//! What the host_sql RE-VFS store refuses, and what it cleans up: the host's storage quota, a
//! host that cannot name one, a plain file transfer it could never hand back, and every object
//! of an account that is deleted.

#[path = "common/sqlite_host.rs"]
mod sqlite_host;
#[path = "common/revfs_support.rs"]
mod support;

use async_trait::async_trait;
use citadel_io::{tokio, ErrorCode};
use citadel_types::proto::TransferType;
use citadel_user::backend::host_sql::{
    HostSqlHandle, SqlHost, SqlRow, SqlStatement, SqlValue, StorageQuota,
};
use citadel_user::backend::BackendConnection;
use sqlite_host::SqliteHost;
use support::*;

fn quota_host(limit: usize) -> HostSqlHandle {
    HostSqlHandle::new(SqliteHost::in_memory(StorageQuota::Bytes(limit as u64)))
}

#[tokio::test]
async fn an_upload_that_would_exceed_the_quota_is_refused_as_storage_full() {
    let host = quota_host(1000 * KIB);
    let backend = connected(&host).await;
    store(&backend, "/a", &[bytes(600 * KIB, 1)]).await.unwrap();

    // Declares only what fits, then sends more: refused by the per-chunk check.
    let mut meta = metadata("/b", &[bytes(10, 2)]);
    let (result, _) = upload(&backend, &meta, &[bytes(600 * KIB, 2)]).await;
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RevfsStorageFull);
    assert!(err.to_string().contains("Storage full"), "{err}");

    // Declares more than fits: refused before a byte is staged.
    meta.plaintext_length = 600 * KIB;
    let (result, statuses) = upload(&backend, &meta, &[bytes(600 * KIB, 2)]).await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::RevfsStorageFull);
    assert!(
        statuses.is_empty(),
        "a refused upload reported {statuses:?}"
    );

    assert_eq!(
        read_back(&backend, "/a").await.unwrap(),
        bytes(600 * KIB, 1)
    );
    assert_eq!(
        (rows(&host, FILES).await, rows(&host, UPLOADS).await),
        (1, 0)
    );
    assert_eq!(rows(&host, CHUNKS).await, 2);
}

#[tokio::test]
async fn replacing_an_object_counts_only_the_new_bytes() {
    let host = quota_host(1000 * KIB);
    let backend = connected(&host).await;
    store(&backend, "/a", &[bytes(600 * KIB, 1)]).await.unwrap();
    store(&backend, "/a", &[bytes(900 * KIB, 2)]).await.unwrap();
    assert_eq!(
        read_back(&backend, "/a").await.unwrap(),
        bytes(900 * KIB, 2)
    );
}

#[tokio::test]
async fn bytes_staged_by_an_unfinished_upload_count_against_the_quota() {
    let host = quota_host(1000 * KIB);
    let backend = connected(&host).await;
    let _ = sql(
        &host,
        "INSERT INTO citadel_revfs_uploads (upload, cid, path, bytes) VALUES ('other', '1', '/o', ?)",
        vec![SqlValue::Integer(600 * KIB as i64)],
    )
    .await;
    // Declares what fits beside the staged bytes, so only the per-chunk check can refuse it.
    let meta = metadata("/a", &[bytes(10, 1)]);
    let (result, _) = upload(&backend, &meta, &[bytes(600 * KIB, 1)]).await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::RevfsStorageFull);
}

struct NoQuotaHost(SqliteHost);

#[async_trait]
impl SqlHost for NoQuotaHost {
    async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
        self.0.execute(statements).await
    }

    fn storage_quota(&self) -> Result<StorageQuota, String> {
        Err("entitlements not loaded".into())
    }
}

#[tokio::test]
async fn a_host_that_cannot_name_a_quota_refuses_the_upload() {
    let host = HostSqlHandle::new(NoQuotaHost(SqliteHost::in_memory(StorageQuota::Unlimited)));
    let backend = connected(&host).await;
    let err = store(&backend, "/a", &[bytes(10, 1)]).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::HostSqlStorageQuotaUnavailable);
    assert!(err.to_string().contains("entitlements not loaded"), "{err}");
    assert_eq!(rows(&host, UPLOADS).await, 0);
}

#[tokio::test]
async fn a_plain_file_transfer_is_refused_rather_than_discarded() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let groups = vec![bytes(10, 1)];
    let mut meta = metadata("/a", &groups);
    meta.transfer_type = TransferType::FileTransfer;
    let (result, _) = upload(&backend, &meta, &groups).await;
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::HostSqlPlainFileTransferUnsupported
    );
}

#[tokio::test]
async fn deleting_an_account_deletes_its_objects_and_no_one_elses() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let _ = sql(
        &host,
        "INSERT INTO citadel_cnacs (cid, is_personal, username, full_name, creation_date, bin) VALUES (?, 0, 'owner', '', '', x'')",
        vec![SqlValue::Text(CID.to_string())],
    )
    .await;
    store(&backend, "/a", &[bytes(700 * KIB, 1)]).await.unwrap();
    store(&backend, "/b", &[bytes(10, 2)]).await.unwrap();
    let _ = sql(
        &host,
        "INSERT INTO citadel_revfs_uploads (upload, cid, path, bytes) VALUES ('staged', ?, '/c', 0)",
        vec![SqlValue::Text(CID.to_string())],
    )
    .await;
    let _ = sql(
        &host,
        "INSERT INTO citadel_revfs_files (cid, path, upload, size, chunks, metadata) VALUES ('7', '/other', 'u7', 0, 0, x'')",
        vec![],
    )
    .await;

    backend.delete_cnac_by_cid(CID).await.unwrap();
    assert_eq!(rows(&host, CHUNKS).await, 0);
    assert_eq!(
        (rows(&host, FILES).await, rows(&host, UPLOADS).await),
        (1, 0)
    );
    assert_eq!(
        read_back(&backend, "/a").await.unwrap_err().code(),
        ErrorCode::RevfsFileNotFound
    );
}

#[tokio::test]
async fn a_purge_deletes_every_object() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    store(&backend, "/a", &[bytes(10, 1)]).await.unwrap();
    let _ = BackendConnection::purge(&backend).await.unwrap();
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, FILES).await),
        (0, 0)
    );
}
