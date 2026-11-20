#![cfg(not(target_family = "wasm"))]
//! RE-VFS objects are sealed under the account's own key before they leave the device. The
//! server stores bytes it cannot open, a group it moves or replaces does not open, and an
//! object stored the old way (under the session's static auxiliary ratchet, which the server
//! also holds) is read and then sealed again.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::host_sql_server::*;
    use crate::sqlite_host::SqliteHost;
    use citadel_crypt::revfs_seal::{self, MAGIC};
    use citadel_crypt::scramble::streaming_crypt_scrambler::BytesSource;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::localhost_revfs_keys;

    const GROUP: usize = 64 * 1024;

    fn object(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    async fn store(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        bytes: Vec<u8>,
    ) -> Result<(), NetworkError> {
        conn.remote
            .remote_encrypted_virtual_filesystem_push_custom_chunking(
                BytesSource::from(bytes),
                VIRTUAL_PATH,
                GROUP,
                SecurityLevel::Standard,
            )
            .await
    }

    async fn rows(host: &HostSqlHandle, sql: &'static str, params: Vec<SqlValue>) -> Vec<SqlRow> {
        let mut out = host.0.execute(vec![SqlStatement { sql, params }]).await;
        out.as_mut().unwrap().remove(0)
    }

    fn blob(value: &SqlValue) -> Vec<u8> {
        match value {
            SqlValue::Blob(b) => b.clone(),
            other => panic!("expected a blob, got {other:?}"),
        }
    }

    fn integer(value: &SqlValue) -> usize {
        match value {
            SqlValue::Integer(n) => *n as usize,
            other => panic!("expected an integer, got {other:?}"),
        }
    }

    /// The object's stored groups, as the server holds them.
    async fn stored_groups(host: &HostSqlHandle) -> Vec<Vec<u8>> {
        let file = rows(
            host,
            "SELECT upload, group_bytes FROM citadel_revfs_files",
            vec![],
        )
        .await;
        let (upload, group_bytes) = (file[0][0].clone(), integer(&file[0][1]));
        let chunks = rows(
            host,
            "SELECT bin FROM citadel_revfs_chunks WHERE upload = ? ORDER BY idx",
            vec![upload],
        )
        .await;
        let bytes: Vec<u8> = chunks.iter().flat_map(|row| blob(&row[0])).collect();
        bytes.chunks(group_bytes).map(<[u8]>::to_vec).collect()
    }

    /// Replaces the stored object's bytes, as a server (or whoever holds its storage) could.
    async fn replace_stored(host: &HostSqlHandle, groups: &[Vec<u8>]) {
        let file = rows(host, "SELECT upload FROM citadel_revfs_files", vec![]).await;
        let upload = file[0][0].clone();
        let bytes: Vec<u8> = groups.concat();
        let statements = vec![
            SqlStatement {
                sql: "DELETE FROM citadel_revfs_chunks WHERE upload = ?",
                params: vec![upload.clone()],
            },
            SqlStatement {
                sql: "INSERT INTO citadel_revfs_chunks (upload, idx, bin) VALUES (?, 0, ?)",
                params: vec![upload.clone(), SqlValue::Blob(bytes.clone())],
            },
            SqlStatement {
                sql: "UPDATE citadel_revfs_files SET size = ?, chunks = 1, group_bytes = ?",
                params: vec![
                    SqlValue::Integer(bytes.len() as i64),
                    SqlValue::Integer(groups[0].len() as i64),
                ],
            },
        ];
        host.0.execute(statements).await.unwrap();
    }

    async fn static_aux(conn: &CitadelClientServerConnection<StackedRatchet>) -> StackedRatchet {
        conn.remote
            .account_manager()
            .get_client_by_cid(conn.cid)
            .await
            .unwrap()
            .expect("the client's account")
            .get_static_auxiliary_ratchet()
    }

    async fn pull(
        conn: &CitadelClientServerConnection<StackedRatchet>,
    ) -> Result<(Vec<u8>, bool), NetworkError> {
        let pulled = conn
            .remote
            .remote_encrypted_virtual_filesystem_pull_resealing(
                VIRTUAL_PATH,
                SecurityLevel::Standard,
                false,
            )
            .await?;
        Ok((std::fs::read(&pulled.path).unwrap(), pulled.resealed))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_stored_object_is_sealed_under_the_accounts_key_and_not_the_servers() {
        let host = SqliteHost::handle();
        let plaintext = object(3 * GROUP);
        let h = host.clone();
        let sent = plaintext.clone();
        let (groups, aux_opens, pulled, key_id) = against_server(host, |conn| async move {
            store(&conn, sent).await.expect("the upload failed");
            let groups = stored_groups(&h).await;
            let aux = static_aux(&conn).await;
            let aux_opens = groups
                .iter()
                .filter(|g| {
                    aux.local_decrypt(g.as_slice(), SecurityLevel::Standard)
                        .is_ok()
                })
                .count();
            let key_id = localhost_revfs_keys().revfs_key(conn.cid).unwrap().id();
            (groups, aux_opens, pull(&conn).await, key_id)
        })
        .await;
        assert_eq!(groups.len(), 3);
        for group in &groups {
            assert_eq!(&group[..4], MAGIC);
            assert_eq!(group[4..12], key_id);
            assert!(!group.windows(64).any(|w| w == &plaintext[..64]));
        }
        assert_eq!(aux_opens, 0, "the server's key opened a stored group");
        assert_eq!(pulled.unwrap(), (plaintext, false));
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_object_stored_the_old_way_is_read_and_sealed_again() {
        let host = SqliteHost::handle();
        let plaintext = object(GROUP / 2);
        let h = host.clone();
        let sent = plaintext.clone();
        let (first, after, second, listed) = against_server(host, |conn| async move {
            store(&conn, sent.clone()).await.expect("the upload failed");
            let aux = static_aux(&conn).await;
            let legacy = aux
                .local_encrypt(sent.as_slice(), SecurityLevel::Standard)
                .unwrap();
            replace_stored(&h, std::slice::from_ref(&legacy)).await;
            let first = pull(&conn).await;
            let after = stored_groups(&h).await;
            let second = pull(&conn).await;
            replace_stored(&h, &[legacy]).await;
            let listed =
                citadel_sdk::fs::reseal(&conn.remote, SecurityLevel::Standard, [VIRTUAL_PATH])
                    .await
                    .map(|pulled| pulled.iter().map(|p| p.resealed).collect::<Vec<_>>());
            (first, after, second, listed)
        })
        .await;
        assert_eq!(first.unwrap(), (plaintext.clone(), true));
        assert_eq!(&after[0][..4], MAGIC, "the object was not sealed again");
        assert_eq!(second.unwrap(), (plaintext, false));
        assert_eq!(listed.unwrap(), vec![true]);
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_push_without_a_key_is_refused_and_stores_nothing() {
        let host = SqliteHost::handle();
        let none: Option<fn(u64) -> Option<RevfsKey>> = None;
        let pushed = against_server_keyed(host.clone(), none, |conn| async move {
            store(&conn, object(GROUP)).await
        })
        .await;
        let err = pushed.expect_err("a push without a key must be refused");
        assert!(
            err.to_string().contains("No RE-VFS key is configured"),
            "{err}"
        );
        assert_eq!(
            count(&host, "SELECT COUNT(*) FROM citadel_revfs_files").await,
            0
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_object_sealed_under_another_key_is_not_opened() {
        let host = SqliteHost::handle();
        let h = host.clone();
        let pulled = against_server(host, |conn| async move {
            store(&conn, object(GROUP))
                .await
                .expect("the upload failed");
            let theirs = RevfsKey::derive(&[9u8; 32], "localhost", conn.cid).unwrap();
            let group = revfs_seal::seal(&theirs, 0, 0, SecurityLevel::Standard, &object(GROUP));
            replace_stored(&h, &[group.unwrap()]).await;
            pull(&conn).await
        })
        .await;
        let err = pulled.expect_err("another account's object was opened");
        assert!(err.to_string().contains("another account's key"), "{err}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn groups_the_server_reorders_do_not_open() {
        let host = SqliteHost::handle();
        let h = host.clone();
        let pulled = against_server(host, |conn| async move {
            store(&conn, object(3 * GROUP))
                .await
                .expect("the upload failed");
            let mut groups = stored_groups(&h).await;
            groups.swap(0, 1);
            replace_stored(&h, &groups).await;
            pull(&conn).await
        })
        .await;
        let err = pulled.expect_err("reordered groups were opened");
        assert!(
            err.to_string().contains("altered, truncated or moved"),
            "{err}"
        );
    }
}
