#![cfg(not(target_family = "wasm"))]
//! A server's admission refusal publishes the check to show (`AdmissionChallenge`), so a client
//! that reaches the server only through the protocol can render it and try again. The challenge
//! reaches the client's error on a refused sign-in and a refused registration, and a server that
//! publishes none sends none.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::*;
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use citadel_user::auth::pq::admission::{challenge_of, AdmissionChallenge};
    use std::sync::Arc;
    use std::time::Duration;

    fn challenge() -> AdmissionChallenge {
        AdmissionChallenge::turnstile("0x4AAAAAAA-public-site-key", Some("acme".into()))
    }

    fn published<T>(result: &Result<T, NetworkError>) -> Option<AdmissionChallenge> {
        result.as_ref().err().and_then(challenge_of).cloned()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn the_challenge_reaches_a_refused_registration_and_sign_in() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::with_grace(Duration::ZERO).publishing(challenge()));
        let (server, addr, _) = server(guarded(policy.clone()), Some(poisoned_argon()), None);
        let user = username("chal");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            let refused = register(&remote, addr, &user, None).await;
            assert_eq!(code(&refused), Some(ErrorCode::PqSignInAdmissionRequired));
            assert_eq!(published(&refused), Some(challenge()), "register lost it");
            // A refused token is not a request for the check: no challenge rides on it.
            let bad = register(&remote, addr, &user, Some("forged")).await;
            assert_eq!(code(&bad), Some(ErrorCode::PqSignInAdmissionFailed));
            assert_eq!(published(&bad), None);
            register(&remote, addr, &user, Some(GOOD)).await?;

            let refused = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
            assert_eq!(code(&refused), Some(ErrorCode::PqSignInAdmissionRequired));
            assert_eq!(published(&refused), Some(challenge()), "sign-in lost it");
            let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
            let conn = sign_in(&remote, &user, factors).await?;
            assert_eq!(
                seen.asked(),
                ["register", "register", "register", "sign-in", "sign-in"]
            );
            conn.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_that_publishes_none_sends_none() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::with_grace(Duration::ZERO));
        let (server, addr, _) = server(guarded(policy), Some(poisoned_argon()), None);
        let user = username("nochal");
        run(server, move |remote, _| async move {
            let refused = register(&remote, addr, &user, None).await;
            assert_eq!(code(&refused), Some(ErrorCode::PqSignInAdmissionRequired));
            assert_eq!(published(&refused), None);
            register(&remote, addr, &user, Some(GOOD)).await?;
            let refused = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
            assert_eq!(code(&refused), Some(ErrorCode::PqSignInAdmissionRequired));
            assert_eq!(published(&refused), None);
            remote.shutdown().await
        })
        .await;
    }
}
