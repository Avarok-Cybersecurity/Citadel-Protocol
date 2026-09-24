#![cfg(not(target_family = "wasm"))]
//! Reading RE-VFS objects back from a server whose storage is host-provided SQL. The backend
//! hands the protocol an object with no path on disk; the send path used to refuse any source
//! without one, so a tenant could store files but never return them.

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
    use citadel_io::tokio;
    use std::time::{Duration, Instant};

    const FILES: &str = "SELECT COUNT(*) FROM citadel_revfs_files";
    const CHUNKS: &str = "SELECT COUNT(*) FROM citadel_revfs_chunks";

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_stored_object_is_pulled_back_byte_for_byte() {
        let host = SqliteHost::handle();
        let (pushed, pulled) = against_server(host.clone(), |conn| async move {
            let pushed = push(&conn, 512 * 1024).await;
            let pulled = citadel_sdk::fs::read(&conn.remote, VIRTUAL_PATH).await;
            (pushed, pulled.map(|path| std::fs::read(path).unwrap()))
        })
        .await;
        pushed.expect("the upload failed");
        let pulled = pulled.expect("the pull failed");
        assert!(
            pulled == std::fs::read(SOURCE).unwrap(),
            "pulled bytes differ"
        );
        assert_eq!(
            count(&host, FILES).await,
            1,
            "a read must not remove the object"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_take_returns_the_object_and_removes_it_from_the_backend() {
        let host = SqliteHost::handle();
        let (taken, read_after) = against_server(host.clone(), |conn| async move {
            push(&conn, 0).await.expect("the upload failed");
            let taken = citadel_sdk::fs::take(&conn.remote, VIRTUAL_PATH)
                .await
                .map(|path| std::fs::read(path).unwrap());
            // The server deletes once the transfer has gone out; give it that moment.
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut read_after = citadel_sdk::fs::read(&conn.remote, VIRTUAL_PATH).await;
            while read_after.is_ok() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
                read_after = citadel_sdk::fs::read(&conn.remote, VIRTUAL_PATH).await;
            }
            (taken, read_after)
        })
        .await;
        let taken = taken.expect("the take failed");
        assert!(
            taken == std::fs::read(SOURCE).unwrap(),
            "taken bytes differ"
        );
        let err = read_after.expect_err("the taken object is still readable");
        assert!(err.to_string().contains("No RE-VFS file"), "{err}");
        assert_eq!(
            (count(&host, FILES).await, count(&host, CHUNKS).await),
            (0, 0)
        );
    }
}
