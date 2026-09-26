#![cfg(not(target_family = "wasm"))]
//! RE-VFS against a server whose accounts live in host-provided SQL (a tenant's Durable Object):
//! an upload is stored and deleted, and when the server cannot store it the uploader is told —
//! with the server's reason — instead of waiting forever for an acknowledgement.

#[cfg(feature = "localhost-testing")]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
mod sqlite_host;

#[cfg(feature = "localhost-testing")]
#[path = "common/host_sql_server.rs"]
mod host_sql_server;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::host_sql_server::*;
    use crate::sqlite_host::SqliteHost;
    use async_trait::async_trait;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use uuid::Uuid;

    /// Refuses every chunk write, as a host whose storage is failing would.
    struct RefusingHost(SqliteHost);

    #[async_trait]
    impl SqlHost for RefusingHost {
        async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
            if statements
                .iter()
                .any(|s| s.sql.starts_with("INSERT INTO citadel_revfs_chunks"))
            {
                return Err("the host refused the write".into());
            }
            self.0.execute(statements).await
        }

        fn storage_quota(&self) -> Result<StorageQuota, String> {
            self.0.storage_quota()
        }
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_upload_is_stored_in_bounded_rows_and_deleted() {
        let host = SqliteHost::handle();
        let (pushed, deleted, pull_after_delete) =
            against_server(host.clone(), |conn| async move {
                // Four groups of 512 KiB: the server receives, splits and commits them in turn.
                let pushed = push(&conn, 512 * 1024).await;
                let deleted = citadel_sdk::fs::delete(&conn.remote, VIRTUAL_PATH).await;
                let pulled = citadel_sdk::fs::read(&conn.remote, VIRTUAL_PATH).await;
                (pushed, deleted, pulled)
            })
            .await;
        pushed.expect("the upload to a host_sql server failed");
        deleted.expect("deleting the stored object failed");
        let err = pull_after_delete.expect_err("a deleted object was pulled");
        assert!(err.to_string().contains("No RE-VFS file"), "{err}");
        assert_eq!(
            count(&host, "SELECT COUNT(*) FROM citadel_revfs_files").await,
            0
        );
        assert_eq!(
            count(&host, "SELECT COUNT(*) FROM citadel_revfs_chunks").await,
            0
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn the_stored_object_holds_every_byte_sent() {
        let host = SqliteHost::handle();
        let pushed = against_server(host.clone(), |conn| async move { push(&conn, 0).await }).await;
        pushed.expect("the upload to a host_sql server failed");
        let plaintext = std::fs::metadata(SOURCE).unwrap().len() as i64;
        let stored = count(&host, "SELECT SUM(LENGTH(bin)) FROM citadel_revfs_chunks").await;
        // What is stored is the client's ciphertext: never shorter than the file.
        assert!(stored >= plaintext, "stored {stored} of {plaintext} bytes");
        assert_eq!(
            count(&host, "SELECT MAX(LENGTH(bin)) FROM citadel_revfs_chunks").await,
            512 * 1024
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_second_multi_group_upload_in_one_session_is_stored_whole() {
        // The session's group ids keep counting across files, so the second file's first group
        // is not group 0; a receiver reading completion off the id stopped after one group.
        let second = std::env::temp_dir().join(format!("revfs-second-{}.bin", Uuid::new_v4()));
        std::fs::write(&second, vec![7u8; 700 * 1024]).unwrap();
        let host = SqliteHost::handle();
        let source = second.clone();
        let (first, replaced) = against_server(host.clone(), |conn| async move {
            let first = push(&conn, 512 * 1024).await;
            (first, push_from(&conn, source, 512 * 1024).await)
        })
        .await;
        std::fs::remove_file(&second).unwrap();
        first.expect("the first upload failed");
        replaced.expect("the second upload in the session failed");
        assert_eq!(
            count(&host, "SELECT COUNT(*) FROM citadel_revfs_files").await,
            1
        );
        let stored = count(&host, "SELECT SUM(LENGTH(bin)) FROM citadel_revfs_chunks").await;
        assert!(
            stored >= 700 * 1024,
            "stored {stored} bytes of a 700 KiB file"
        );
        assert!(
            stored < 1024 * 1024,
            "the replaced object's {stored} bytes remain"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_write_the_server_cannot_make_fails_the_upload_instead_of_hanging_it() {
        // One group: the whole file is queued before the backend's write fails, so the uploader
        // has nothing left to send and learns the outcome only if the server tells it.
        let host = HostSqlHandle::new(RefusingHost(SqliteHost::in_memory(StorageQuota::Unlimited)));
        let pushed = against_server(host, |conn| async move { push(&conn, 0).await }).await;
        let err = pushed.expect_err("an upload the server could not store succeeded");
        assert!(err.to_string().contains("refused"), "{err}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_upload_over_the_quota_fails_as_storage_full() {
        let host = HostSqlHandle::new(SqliteHost::in_memory(StorageQuota::Bytes(1024 * 1024)));
        let pushed = against_server(host.clone(), |conn| async move { push(&conn, 0).await }).await;
        let err = pushed.expect_err("an upload over the quota succeeded");
        assert!(err.to_string().contains("Storage full"), "{err}");
        assert_eq!(
            count(&host, "SELECT COUNT(*) FROM citadel_revfs_files").await,
            0
        );
    }
}
