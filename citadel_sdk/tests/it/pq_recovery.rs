#![cfg(not(target_family = "wasm"))]
//! Account recovery on a new device, end to end: a device that holds nothing recovers an account
//! with its phrase, which revokes every other device; a forgotten password is replaced from the
//! phrase session; a regenerated phrase retires the old one; and every wrong, foreign, retired or
//! throttled attempt fails alike.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use crate::common::recovery::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;

    /// The whole lost-device path: B recovers, A is revoked, the phrase session sets a password,
    /// the old password stops working, the new one signs in to a full session.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_new_device_recovers_the_account_and_the_old_one_is_revoked() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("rec");
        let (server, device_b) = with_device(server);
        run(server, move |remote_a, mut events| async move {
            let phrase = with_phrase(&remote_a, addr, &user).await?;
            let held = login(&remote_a, &user, PASSWORD).await?;
            let remote_b = device_b.await.unwrap();

            let recovered = recover(&remote_b, addr, &user, &phrase).await?;
            assert_eq!(recovered.cid, held.cid);
            // The old device's live session is ended by the server.
            let ended = async {
                while let Some(event) = events.recv().await {
                    if let NodeResult::Disconnect(dc) = event {
                        if dc.cid_opt == Some(held.cid) {
                            return;
                        }
                    }
                }
                panic!("the event stream closed");
            };
            let deadline = std::time::Duration::from_secs(30);
            let ended = tokio::time::timeout(deadline, ended).await;
            assert!(
                ended.is_ok(),
                "the old device's session survived the recovery"
            );
            // A request on the ended session is answered, not left waiting.
            let rekey = tokio::time::timeout(deadline, held.rekey()).await;
            assert!(
                matches!(rekey, Ok(Err(_))),
                "rekey on an ended session: {rekey:?}"
            );
            let revoked = login(&remote_a, &user, PASSWORD).await;
            assert!(revoked.is_err(), "the old device's bundle still signs in");

            let conn = phrase_session(&remote_b, &user, &phrase).await?;
            conn.set_password(NEW_PASSWORD, SignInFactors::default())
                .await?;
            conn.disconnect().await?;
            assert!(
                login(&remote_b, &user, PASSWORD).await.is_err(),
                "the old password"
            );
            let full = login(&remote_b, &user, NEW_PASSWORD).await?;
            assert!(full.rekey().await?.is_some());
            let peers = full.get_local_group_peers(user.as_str(), None).await;
            assert!(peers.is_ok(), "the new password's session is not full");
            full.disconnect().await?;

            // The phrase is reusable: A, lost in turn, comes back the same way.
            let again = recover(&remote_a, addr, &user, &phrase).await?;
            assert_eq!(again.cid, recovered.cid);
            assert!(
                login(&remote_b, &user, NEW_PASSWORD).await.is_err(),
                "B kept its bundle"
            );
            let back = login(&remote_a, &user, NEW_PASSWORD).await?;
            back.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_wrong_or_foreign_phrase_fails_like_an_unknown_account() {
        citadel_logging::setup_log();
        // Four failures in a row: a throttle wide enough that it is the phrase being judged here.
        let loose = ThrottlePolicy {
            max_failures: 100,
            ..ThrottlePolicy::RECOMMENDED
        };
        let misc = pq_settings_throttled(loose);
        let (server, addr, _) = server(misc, Some(poisoned_argon()), None);
        let (alice, bob) = (username("alice"), username("bob"));
        let (server, device_b) = with_device(server);
        run(server, move |remote, _| async move {
            let alices = with_phrase(&remote, addr, &alice).await?;
            let bobs = with_phrase(&remote, addr, &bob).await?;
            let device = device_b.await.unwrap();
            let random = RecoveryPhrase::new(RecoverySeed::generate(), DOMAIN)?;
            let elsewhere = RecoveryPhrase::new(alices.seed().clone(), "example.com")?;

            assert_failed(
                recover(&device, addr, &alice, &random).await,
                "a random phrase",
            );
            assert_failed(recover(&device, addr, &alice, &bobs).await, "bob's phrase");
            assert_failed(
                recover(&device, addr, &alice, &elsewhere).await,
                "another domain",
            );
            let ghost = username("ghost");
            assert_failed(
                recover(&device, addr, &ghost, &alices).await,
                "an unknown name",
            );

            // Nothing changed: alice's own device still signs in, and her phrase still works.
            let conn = login(&remote, &alice, PASSWORD).await?;
            conn.disconnect().await?;
            let _ = recover(&device, addr, &alice, &alices).await?;
            remote.shutdown().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_regenerated_phrase_retires_the_old_one() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("regen");
        let (server, device_b) = with_device(server);
        run(server, move |remote, _| async move {
            let old = with_phrase(&remote, addr, &user).await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            let new = phrase(&regenerate(&conn, password()).await?);
            conn.disconnect().await?;
            let device = device_b.await.unwrap();

            assert_failed(
                recover(&device, addr, &user, &old).await,
                "the retired phrase",
            );
            let refused = phrase_session(&remote, &user, &old).await;
            assert!(refused.is_err(), "the retired phrase signed in");
            let _ = recover(&device, addr, &user, &new).await?;
            remote.shutdown().await
        })
        .await;
    }

    /// One wrong recovery locks the account's key under a one-failure policy; the right phrase is
    /// then refused alike until the lockout ends. Control: drop the server's `throttle_admit`
    /// check in the recovery lane and the right phrase is admitted.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_attempt_over_the_throttle_is_refused_even_with_the_right_phrase() {
        citadel_logging::setup_log();
        let tight = ThrottlePolicy {
            max_failures: 1,
            ..ThrottlePolicy::RECOMMENDED
        };
        let (server, addr, _) = server(pq_settings_throttled(tight), Some(poisoned_argon()), None);
        let user = username("throttle");
        let (server, device_b) = with_device(server);
        run(server, move |remote, _| async move {
            let right = with_phrase(&remote, addr, &user).await?;
            let device = device_b.await.unwrap();
            let wrong = RecoveryPhrase::new(RecoverySeed::generate(), DOMAIN)?;
            assert_failed(
                recover(&device, addr, &user, &wrong).await,
                "the wrong phrase",
            );
            assert_failed(
                recover(&device, addr, &user, &right).await,
                "over the throttle",
            );
            let refused = phrase_session(&remote, &user, &right).await;
            assert!(refused.is_err(), "a phrase sign-in over the throttle");
            remote.shutdown().await
        })
        .await;
    }
}
