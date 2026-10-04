#![cfg(not(target_family = "wasm"))]
//! Post-quantum sign-in end to end, client and server over a real connection, since the Argon2
//! sunset: the only way a password account registers and signs in. The server links no Argon2 at
//! all on wasm32 (ci/no-classical-signatures.sh); here it is shown never to need it.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_user::server_misc_settings::ServerMiscSettings;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_post_quantum_account_registers_and_signs_in() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(pq_settings(), None);
        let user = username("pq");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            let mode = server_mode(&slot, &user).await;
            assert!(mode.post_quantum, "registered as {mode:?}");

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

    /// A password registration that skips the post-quantum exchange (what every client did before
    /// it) is refused, and no account is created: nothing is left to keep such an account with.
    /// (The server's own refusal of one, and the "update your app" a client below 0.12 gets, are
    /// `pq_sign_in::tests` in citadel_proto.)
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_password_registration_without_its_factors_is_refused() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(pq_settings(), None);
        let user = username("pql");
        run(server, move |remote, _| async move {
            let refused = register_legacy(&remote, addr, &user)
                .await
                .expect_err("a password account without factors was created");
            // The client refuses before anything reaches the server: the registration lacks the
            // password factor it would need.
            assert!(
                refused
                    .to_string()
                    .starts_with("This sign-in needs a factor"),
                "refused for another reason: {refused}"
            );
            let held = slot.lock().await.clone().expect("server remote loaded");
            assert!(held
                .account_manager()
                .get_client_by_username(&user)
                .await
                .unwrap()
                .is_none());
            remote.shutdown().await
        })
        .await;
    }

    /// A server without post-quantum settings offers passwordless accounts only: a password
    /// registration with it is refused rather than falling back to a server-side hash.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_without_pq_settings_refuses_password_accounts() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(ServerMiscSettings::default(), None);
        let user = username("leg");
        run(server, move |remote, _| async move {
            let refused = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await;
            assert!(refused.is_err(), "registered a password account");
            remote.shutdown().await
        })
        .await;
    }
}
