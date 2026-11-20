#![cfg(not(target_family = "wasm"))]
//! What a phrase session and a full session may change: the phrase session manages credentials
//! and nothing else; a full session changes the password only by proving the current one.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use crate::common::recovery::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;

    /// The phrase session manages credentials and nothing else; a code is not regenerated there.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_phrase_session_only_manages_credentials() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("scope");
        run(server, move |remote, _| async move {
            let old = with_phrase(&remote, addr, &user).await?;
            let conn = phrase_session(&remote, &user, &old).await?;
            let normal = conn.get_local_group_peers(user.as_str(), None).await;
            assert!(normal.is_err(), "a phrase session ran a normal request");
            let codes = conn.manage_sign_in(
                SignInManagementOp::RegenerateRecoveryCodes,
                SignInFactors::default(),
            );
            assert!(codes.await.is_err(), "a phrase session regenerated codes");
            let rename = conn.manage_sign_in(
                SignInManagementOp::RenameCredential {
                    id: 1,
                    label: "x".into(),
                },
                SignInFactors::default(),
            );
            assert!(rename.await.is_err(), "a phrase session renamed a factor");
            let listed = conn.manage_sign_in(
                SignInManagementOp::ListCredentials,
                SignInFactors::default(),
            );
            assert!(matches!(
                listed.await?,
                SignInManagementOutcome::Credentials { .. }
            ));
            let new = phrase(&regenerate(&conn, SignInFactors::default()).await?);
            conn.disconnect().await?;
            assert!(
                phrase_session(&remote, &user, &old).await.is_err(),
                "the old phrase"
            );
            let conn = phrase_session(&remote, &user, &new).await?;
            conn.shutdown_kernel().await
        })
        .await;
    }

    /// A full session changes the password only with the current one.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_full_session_changes_the_password_with_the_current_one() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("change");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(
                    addr,
                    user.as_str(),
                    user.as_str(),
                    PASSWORD,
                    CertVerification::SelfSignedAccepted,
                )
                .await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            let bare = conn
                .set_password(NEW_PASSWORD, SignInFactors::default())
                .await;
            assert!(
                bare.is_err(),
                "a full session changed the password without it"
            );
            let wrong = SignInFactors::password("not the password");
            assert!(conn.set_password(NEW_PASSWORD, wrong).await.is_err());
            conn.set_password(NEW_PASSWORD, password()).await?;
            conn.disconnect().await?;
            assert!(
                login(&remote, &user, PASSWORD).await.is_err(),
                "the old password"
            );
            let conn = login(&remote, &user, NEW_PASSWORD).await?;
            conn.shutdown_kernel().await
        })
        .await;
    }

    /// A step-up is a guess at the account's factors like a sign-in: one wrong current password
    /// locks the account under a one-failure policy, and the right one is then refused. Control:
    /// drop the throttle check at management Begin and the right password is admitted.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_step_up_over_the_throttle_is_refused() {
        citadel_logging::setup_log();
        let tight = ThrottlePolicy {
            max_failures: 1,
            ..ThrottlePolicy::RECOMMENDED
        };
        let (server, addr, _) = server(pq_settings_throttled(tight), Some(poisoned_argon()), None);
        let user = username("stepup");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(
                    addr,
                    user.as_str(),
                    user.as_str(),
                    PASSWORD,
                    CertVerification::SelfSignedAccepted,
                )
                .await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            let wrong = SignInFactors::password("not the password");
            assert!(conn.set_password(NEW_PASSWORD, wrong).await.is_err());
            let refused = conn.set_password(NEW_PASSWORD, password()).await;
            assert!(refused.is_err(), "a step-up over the throttle");
            conn.shutdown_kernel().await
        })
        .await;
    }
}
