#![cfg(not(target_family = "wasm"))]
//! Post-quantum sign-in end to end, client and server over a real connection.
//!
//! The server below is given Argon2 parameters no Argon2 implementation accepts (zero lanes), so
//! any password hashing it attempted would fail the run: a post-quantum account registers and
//! signs in all the same. The second test is the control that the poison bites.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_user::server_misc_settings::ServerMiscSettings;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_post_quantum_account_registers_and_signs_in_without_server_argon() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("pq");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            let mode = server_mode(&slot, &user).await;
            assert!(mode.post_quantum && !mode.argon, "registered as {mode:?}");

            let conn = login(&remote, &user, PASSWORD).await?;
            // The sign-in's session key is in both sides' pre-shared keys: if either side lacked
            // it, the channel could not ratchet forward.
            assert!(conn.rekey().await?.is_some());
            assert!(conn.rekey().await?.is_some());
            conn.disconnect().await?;

            let wrong = login(&remote, &user, "battery horse correct").await;
            assert!(wrong.is_err(), "a wrong password signed in");
            let again = login(&remote, &user, PASSWORD).await?;
            assert!(again.rekey().await?.is_some());
            again.shutdown_kernel().await
        })
        .await;
    }

    /// The control for the test above: the same poisoned server cannot register a legacy account,
    /// because that path does hash on the server.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn the_poisoned_server_cannot_register_a_legacy_account() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("pql");
        run(server, move |remote, _| async move {
            let refused = register_legacy(&remote, addr, &user).await;
            assert!(refused.is_err(), "the server hashed with zero lanes?");
            remote.shutdown().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_legacy_account_upgrades_at_its_next_login() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(pq_settings(), None, None);
        let user = username("upg");
        run(server, move |remote, _| async move {
            register_legacy(&remote, addr, &user).await?;
            assert!(server_mode(&slot, &user).await.argon);

            // A legacy login, which carries the upgrade.
            let conn = login(&remote, &user, PASSWORD).await?;
            assert!(conn.rekey().await?.is_some());
            conn.disconnect().await?;
            let mode = server_mode(&slot, &user).await;
            assert!(mode.post_quantum && !mode.argon, "not upgraded: {mode:?}");

            // From now on the account signs in post-quantum, and only with the right password.
            assert!(login(&remote, &user, "wrong password here").await.is_err());
            let conn = login(&remote, &user, PASSWORD).await?;
            assert!(conn.rekey().await?.is_some());
            conn.shutdown_kernel().await
        })
        .await;
    }

    /// A server without post-quantum settings keeps the legacy path end to end: the client offers
    /// sign-in, is answered with a legacy challenge, and registers and logs in with Argon2.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_without_pq_settings_keeps_the_legacy_path() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(ServerMiscSettings::default(), None, None);
        let user = username("leg");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            assert!(server_mode(&slot, &user).await.argon);
            let conn = login(&remote, &user, PASSWORD).await?;
            assert!(conn.rekey().await?.is_some());
            conn.disconnect().await?;
            assert!(server_mode(&slot, &user).await.argon);
            assert!(login(&remote, &user, "wrong password here").await.is_err());
            remote.shutdown().await
        })
        .await;
    }
}
