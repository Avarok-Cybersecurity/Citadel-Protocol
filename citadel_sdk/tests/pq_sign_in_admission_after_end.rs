#![cfg(not(target_family = "wasm"))]
//! Admission after the server has ENDED the session: a clean close leaves no held session to
//! recognise the reconnect's resume token, so the server remembers the token for the policy's
//! `resume_grace`. Within it the reconnect is not asked; after it, it is.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::*;
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// Signs `user` in past the check, ends the session, and waits until the server has
    /// dropped it too, so only the ended-session memory can recognise the next login.
    async fn sign_in_then_end(
        remote: &NodeRemote<StackedRatchet>,
        server: &Slot,
        user: &str,
    ) -> Result<u64, NetworkError> {
        let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
        let conn = sign_in(remote, user, factors).await?;
        let cid = conn.cid;
        conn.disconnect().await?;
        let server = server.lock().await.clone().expect("server remote loaded");
        for _ in 0..200 {
            let held = server.sessions().await?.sessions;
            if !held.iter().any(|session| session.cid == cid) {
                return Ok(cid);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(NetworkError::msg(
            "the server never dropped the ended session",
        ))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_after_the_session_ended_is_not_asked_within_the_grace() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::with_grace(Duration::from_secs(900)));
        let (server, addr, slot) = server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let user = username("admend");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            register(&remote, addr, &user, Some(GOOD)).await?;
            let cid = sign_in_then_end(&remote, &slot, &user).await?;
            let again = sign_in(&remote, &user, SignInFactors::password(PASSWORD))
                .await
                .map_err(|err| NetworkError::msg(format!("the reconnect was asked: {err}")))?;
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
    async fn a_reconnect_after_the_grace_is_asked() {
        citadel_logging::setup_log();
        let grace = Duration::from_secs(1);
        let policy = Arc::new(Turnstile::with_grace(grace));
        let (server, addr, slot) = server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let user = username("admlate");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            register(&remote, addr, &user, Some(GOOD)).await?;
            sign_in_then_end(&remote, &slot, &user).await?;
            tokio::time::sleep(grace * 2).await;
            let late = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
            assert_eq!(code(&late), Some(ErrorCode::PqSignInAdmissionRequired));
            assert_eq!(seen.asked(), ["register", "sign-in", "sign-in"]);
            remote.shutdown().await
        })
        .await;
    }
}
