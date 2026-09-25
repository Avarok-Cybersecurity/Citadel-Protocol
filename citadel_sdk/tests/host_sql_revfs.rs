#![cfg(not(target_family = "wasm"))]
//! RE-VFS against a server whose accounts live in host-provided SQL (a tenant's Durable Object):
//! an upload is stored and deleted, and when the server cannot store it the uploader is told —
//! with the server's reason — instead of waiting forever for an acknowledgement.

#[cfg(feature = "localhost-testing")]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
mod sqlite_host;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::sqlite_host::SqliteHost;
    use async_trait::async_trait;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;
    use futures::StreamExt;
    use std::path::PathBuf;
    use std::time::Duration;
    use uuid::Uuid;

    /// Long enough for a slow machine; an uploader left waiting (the defect) cannot pass it.
    const MUST_FINISH_WITHIN: Duration = Duration::from_secs(60);
    const SOURCE: &str = "../resources/TheBridge.pdf";
    const VIRTUAL_PATH: &str = "/home/john.doe/TheBridge.pdf";

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

    /// Accepts every transfer and outlives its failures, as the workspace server's kernel does
    /// (the SDK's accept-all prefab ends the node on the first failed transfer).
    #[derive(Default)]
    struct StorageServerKernel;

    #[async_trait]
    impl NetKernel<StackedRatchet> for StorageServerKernel {
        fn load_remote(&mut self, _: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_node_event_received(
            &self,
            message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) =
                message
            {
                handle.accept()?;
                drop(tokio::spawn(async move {
                    while let Some(status) = handle.next().await {
                        log::info!(target: "citadel", "server-side transfer status: {status:?}");
                    }
                }));
            }
            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    async fn count(host: &HostSqlHandle, sql: &'static str) -> i64 {
        let rows = host
            .0
            .execute(vec![SqlStatement {
                sql,
                params: vec![],
            }])
            .await
            .unwrap();
        match rows[0][0][0] {
            SqlValue::Integer(n) => n,
            ref other => panic!("count was {other:?}"),
        }
    }

    /// Runs `body` as a client of a server storing into `host`, returning what `body` returned.
    async fn against_server<F, Fut, T>(host: HostSqlHandle, body: F) -> T
    where
        F: FnOnce(CitadelClientServerConnection<StackedRatchet>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send,
        T: Send + 'static,
    {
        citadel_logging::setup_log();
        let (server, server_addr) = server_test_node(StorageServerKernel, |b| {
            let _ = b.with_backend(BackendType::HostSql(host));
        });
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        let settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, Uuid::new_v4())
                .disable_udp()
                .build()
                .unwrap();
        let client_kernel =
            SingleClientServerConnectionKernel::new(settings, move |conn| async move {
                let out = body(conn).await;
                let _ = tx.lock().unwrap().take().unwrap().send(out);
                Ok(())
            });
        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        // Polled here, not spawned: a node future is not `Send` in every feature set.
        let mut rx = rx;
        tokio::time::timeout(MUST_FINISH_WITHIN, async move {
            tokio::pin!(server);
            tokio::pin!(client);
            tokio::select! {
                out = &mut rx => return out.expect("the client kernel ended without reporting"),
                res = &mut server => panic!("the server ended first: {:?}", res.map(|_| ())),
                res = &mut client => {
                    if let Err(err) = res {
                        panic!("the client kernel failed: {err:?}");
                    }
                }
            }
            rx.await.expect("the client kernel ended without reporting")
        })
        .await
        .expect("the client never finished: an upload or request was left waiting")
    }

    async fn push(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        chunk_size: usize,
    ) -> Result<(), NetworkError> {
        push_from(conn, PathBuf::from(SOURCE), chunk_size).await
    }

    async fn push_from(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        source: PathBuf,
        chunk_size: usize,
    ) -> Result<(), NetworkError> {
        conn.remote
            .remote_encrypted_virtual_filesystem_push_custom_chunking(
                source,
                VIRTUAL_PATH,
                chunk_size,
                SecurityLevel::Standard,
            )
            .await
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
