//! The host_sql backend's RE-VFS store: an object streamed in comes back byte for byte in
//! bounded rows, a re-upload replaces it whole, and a failure is returned (never a hang) and
//! leaves the previous object intact.

#[path = "common/sqlite_host.rs"]
mod sqlite_host;
#[path = "common/revfs_support.rs"]
mod support;

use citadel_io::tokio::sync::mpsc::unbounded_channel;
use citadel_io::{tokio, ErrorCode};
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::ObjectTransferStatus;
use citadel_user::backend::host_sql::StorageQuota;
use citadel_user::backend::BackendConnection;
use sqlite_host::SqliteHost;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::*;

#[tokio::test]
async fn an_object_round_trips_byte_for_byte_in_bounded_rows_and_is_gone_once_deleted() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    // A group over three chunk rows, one exactly one row, one tiny.
    let groups = vec![bytes(1200 * KIB, 1), bytes(512 * KIB, 2), bytes(10, 3)];
    let meta = metadata("/docs/report.pdf", &groups);

    let (result, statuses) = upload(&backend, &meta, &groups).await;
    result.unwrap();
    assert!(matches!(
        statuses.as_slice(),
        [ObjectTransferStatus::ReceptionBeginning(path, _)] if path == &PathBuf::from("/docs/report.pdf")
    ));
    assert_eq!(
        read_back(&backend, "/docs/report.pdf").await.unwrap(),
        groups.concat()
    );
    let (_, stored) = backend
        .revfs_get_file_info(CID, "/docs/report.pdf".into())
        .await
        .unwrap();
    assert_eq!(stored.object_id, meta.object_id);
    assert!(matches!(
        stored.get_security_level(),
        Some(SecurityLevel::Reinforced)
    ));
    assert_eq!(rows(&host, CHUNKS).await, 5);
    assert_eq!(
        rows(&host, "SELECT MAX(LENGTH(bin)) FROM citadel_revfs_chunks").await,
        512 * KIB as i64
    );
    assert_eq!(rows(&host, UPLOADS).await, 0);
    assert_eq!(
        rows(&host, "SELECT group_bytes FROM citadel_revfs_files").await,
        1200 * KIB as i64,
        "the object must remember the size of the groups it arrived in"
    );

    backend
        .revfs_delete(CID, "/docs/report.pdf".into())
        .await
        .unwrap();
    let err = read_back(&backend, "/docs/report.pdf").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RevfsFileNotFound);
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, FILES).await),
        (0, 0)
    );
    let again = backend.revfs_delete(CID, "/docs/report.pdf".into()).await;
    assert_eq!(again.unwrap_err().code(), ErrorCode::RevfsFileNotFound);
}

#[tokio::test]
async fn a_path_is_normalized_and_validated_as_the_file_backend_does() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let groups = vec![bytes(10, 1)];
    store(&backend, "\\docs\\a.txt", &groups).await.unwrap();
    assert_eq!(
        read_back(&backend, "/docs/a.txt").await.unwrap(),
        groups.concat()
    );
    assert!(store(&backend, "relative.txt", &groups).await.is_err());
}

#[tokio::test]
async fn a_reupload_replaces_the_object_whole() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    store(&backend, "/a", &[bytes(900 * KIB, 7), bytes(900 * KIB, 8)])
        .await
        .unwrap();
    let second = vec![bytes(100, 9)];
    store(&backend, "/a", &second).await.unwrap();

    assert_eq!(read_back(&backend, "/a").await.unwrap(), second.concat());
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, FILES).await),
        (1, 1)
    );
}

#[tokio::test]
async fn a_failed_write_ends_the_upload_while_the_sender_is_open_and_keeps_the_old_object() {
    let (host, armed) = RefusingHost::handle(StorageQuota::Unlimited);
    let backend = connected(&host).await;
    let old = vec![bytes(64, 1)];
    store(&backend, "/a", &old).await.unwrap();
    armed.store(true, Ordering::SeqCst);

    let groups = vec![bytes(10, 2), bytes(10, 3)];
    let meta = metadata("/a", &groups);
    let (tx, rx) = unbounded_channel();
    tx.send(groups[0].clone()).unwrap();
    let (status_tx, _status_rx) = unbounded_channel();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        backend.stream_object_to_backend(rx, &meta, status_tx),
    )
    .await
    .expect("a failed write must end the upload, not wait for more input");
    let err = result.unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
    assert!(
        tx.send(groups[1].clone()).is_err(),
        "the stream was not released"
    );

    armed.store(false, Ordering::SeqCst);
    assert_eq!(read_back(&backend, "/a").await.unwrap(), old.concat());
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, UPLOADS).await),
        (1, 0)
    );
}

#[tokio::test]
async fn a_stream_that_ends_early_stores_nothing_and_keeps_the_old_object() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    let old = vec![bytes(64, 1)];
    store(&backend, "/a", &old).await.unwrap();

    let groups = vec![bytes(10, 2), bytes(10, 3), bytes(10, 4)];
    let meta = metadata("/a", &groups);
    let (result, _) = upload(&backend, &meta, &groups[..2]).await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::RevfsUploadIncomplete);
    assert_eq!(read_back(&backend, "/a").await.unwrap(), old.concat());
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, UPLOADS).await),
        (1, 0)
    );
}

#[tokio::test]
async fn a_node_start_discards_uploads_it_never_finished() {
    let host = SqliteHost::handle();
    let mut backend = connected(&host).await;
    store(&backend, "/kept", &[bytes(10, 1)]).await.unwrap();
    let _ = sql(
        &host,
        "INSERT INTO citadel_revfs_uploads (upload, cid, path, bytes) VALUES ('dead', '4242', '/x', 3)",
        vec![],
    )
    .await;
    let _ = sql(
        &host,
        "INSERT INTO citadel_revfs_chunks (upload, idx, bin) VALUES ('dead', 0, x'010203')",
        vec![],
    )
    .await;

    BackendConnection::connect(&mut backend).await.unwrap();
    assert_eq!(
        (rows(&host, CHUNKS).await, rows(&host, UPLOADS).await),
        (1, 0)
    );
    assert_eq!(read_back(&backend, "/kept").await.unwrap(), bytes(10, 1));
}

#[tokio::test]
async fn a_stored_object_whose_rows_disagree_is_an_error_not_a_splice() {
    let host = SqliteHost::handle();
    let backend = connected(&host).await;
    store(&backend, "/a", &[bytes(1100 * KIB, 1)])
        .await
        .unwrap();
    store(&backend, "/b", &[bytes(10, 2)]).await.unwrap();

    let _ = sql(
        &host,
        "DELETE FROM citadel_revfs_chunks WHERE idx = 1",
        vec![],
    )
    .await;
    let err = read_back(&backend, "/a").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RevfsChangedDuringRead);

    let _ = sql(
        &host,
        "UPDATE citadel_revfs_files SET size = size + 1 WHERE path = '/b'",
        vec![],
    )
    .await;
    let err = read_back(&backend, "/b").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RevfsChangedDuringRead);
}
