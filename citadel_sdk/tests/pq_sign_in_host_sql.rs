#![cfg(not(target_family = "wasm"))]
//! Post-quantum sign-in against a server whose accounts live in host-provided SQL, as a tenant's
//! Durable Object stores them: every read of the record comes back from SQLite, not memory.

#[cfg(feature = "localhost-testing")]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
mod sqlite_host;

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use crate::sqlite_host::SqliteHost;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_host_sql_server_registers_and_signs_in_a_post_quantum_account() {
        citadel_logging::setup_log();
        let backend = BackendType::HostSql(SqliteHost::handle());
        let (server, addr, slot) = server(pq_settings(), Some(poisoned_argon()), Some(backend));
        let user = username("pqsql");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            let mode = server_mode(&slot, &user).await;
            assert!(mode.post_quantum && !mode.argon, "registered as {mode:?}");

            let conn = login(&remote, &user, PASSWORD).await?;
            assert!(conn.rekey().await?.is_some());
            conn.disconnect().await?;
            assert!(login(&remote, &user, "not the password").await.is_err());
            let again = login(&remote, &user, PASSWORD).await?;
            assert!(again.rekey().await?.is_some());
            again.shutdown_kernel().await
        })
        .await;
    }
}
