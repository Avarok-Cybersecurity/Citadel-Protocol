#![cfg(not(target_family = "wasm"))]
//! Admission: a server that requires a token (a Turnstile response) for each FRESH sign-in and
//! registration. The token travels inside the post-quantum channel; a missing one is refused as
//! `PqSignInAdmissionRequired`, a bad one as `PqSignInAdmissionFailed`, a good one admitted. A
//! recovery, with a code or the phrase, is asked as `recover`. A reconnect whose resume token the
//! held session recognises is not asked.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::*;
    use crate::common::half_open::{login_after_local_teardown, standard, SeveringProxy};
    use crate::common::pq::*;
    use crate::common::recovery::{asking, DOMAIN};
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use citadel_user::auth::pq::admission::AdmissionKind;
    use std::sync::Arc;
    use std::time::Duration;

    /// Longer than any test here: a session that ends in one is still within it.
    const GRACE: Duration = Duration::from_secs(900);

    fn turnstile() -> Arc<Turnstile> {
        Arc::new(Turnstile::with_grace(GRACE))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_missing_token_and_a_bad_one_are_refused_and_a_good_one_admitted() {
        citadel_logging::setup_log();
        let policy = turnstile();
        let (server, addr, _) = server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let user = username("adm");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            let missing = register(&remote, addr, &user, None).await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let bad = register(&remote, addr, &user, Some("forged")).await;
            assert_eq!(code(&bad), Some(ErrorCode::PqSignInAdmissionFailed));
            register(&remote, addr, &user, Some(GOOD)).await?;

            let missing = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let factors = SignInFactors::password(PASSWORD).with_admission("forged");
            let bad = sign_in(&remote, &user, factors).await;
            assert_eq!(code(&bad), Some(ErrorCode::PqSignInAdmissionFailed));
            let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
            let conn = sign_in(&remote, &user, factors).await?;
            assert!(conn.rekey().await?.is_some());
            assert_eq!(
                seen.asked(),
                ["register", "register", "register", "sign-in", "sign-in", "sign-in"]
            );
            conn.shutdown_kernel().await
        })
        .await;
    }

    /// Recovery is the surface a guesser needs nothing for, so it is asked like a fresh sign-in.
    /// Control: restore the recovery exemption in `admission::sign_in` and the phrase sign-in
    /// without a token is admitted.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_recovery_is_asked_like_a_fresh_sign_in() {
        citadel_logging::setup_log();
        let policy = turnstile();
        let (server, addr, _) = server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let (server, device) = with_device(server);
        let user = username("admrec");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            let reg = register(&remote, addr, &user, Some(GOOD)).await?;
            let words = reg.recovery_phrase.expect("a new account gets a phrase");
            let phrase = RecoveryPhrase::new(RecoverySeed::parse(&words.join(" "))?, DOMAIN)?;
            let factors = SignInFactors::recovery_phrase(phrase.clone());
            let missing = sign_in(&remote, &user, factors.clone()).await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let console = sign_in(&remote, &user, factors.with_admission(GOOD)).await?;
            console.disconnect().await?;

            let device = device.await.unwrap();
            let ask = asking(&user, &phrase);
            let missing = device.recover(addr, ask.clone(), Default::default(), None);
            let missing = missing.await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let ask = AccountRecovery {
                admission: Some(GOOD.into()),
                ..ask
            };
            let _ = device.recover(addr, ask, Default::default(), None).await?;
            let asked = ["register", "recover", "recover", "recover", "recover"];
            assert_eq!(seen.asked(), asked);
            remote.shutdown().await
        })
        .await;
    }

    /// The client's link dies without the server seeing it, so the server still holds the
    /// session; the reconnect presents that session's resume token and is not asked again.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_resume_token_reconnect_is_not_asked() {
        citadel_logging::setup_log();
        let policy = turnstile();
        let (server, server_addr, _) =
            server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let proxy = SeveringProxy::start(server_addr).await;
        let user = username("admres");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            register(&remote, proxy.addr, &user, Some(GOOD)).await?;
            let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
            let first = sign_in(&remote, &user, factors).await?;
            let cid = first.cid;
            proxy.sever();
            let again = login_after_local_teardown(&remote, &user, PASSWORD, standard(false))
                .await
                .map_err(|err| NetworkError::msg(format!("the reconnect was refused: {err}")))?;
            assert_eq!(again.cid, cid);
            assert_eq!(
                seen.asked(),
                ["register", "sign-in"],
                "the reconnect was asked"
            );
            again.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_legacy_registration_is_asked_too() {
        citadel_logging::setup_log();
        let policy = turnstile();
        let (server, addr, _) = server(guarded(policy.clone()), None, None);
        let user = username("admleg");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            // No PQ_START: the registration is legacy, and is asked at STAGE2 instead.
            let refused = register_legacy(&remote, addr, &user).await;
            let message = refused.expect_err("a legacy registration skipped admission");
            assert_eq!(
                message.into_string(),
                ErrorCode::PqSignInAdmissionRequired.raw_string()
            );
            assert_eq!(seen.asked(), ["register"]);
            remote.shutdown().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn without_a_policy_everyone_is_admitted() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("admnone");
        run(server, move |remote, _| async move {
            register(&remote, addr, &user, None).await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            conn.shutdown_kernel().await
        })
        .await;
    }

    #[test]
    fn the_actions_are_sign_in_register_and_recover() {
        assert_eq!(AdmissionKind::SignIn.action(), "sign-in");
        assert_eq!(AdmissionKind::Register.action(), "register");
        assert_eq!(AdmissionKind::Recover.action(), "recover");
    }
}
