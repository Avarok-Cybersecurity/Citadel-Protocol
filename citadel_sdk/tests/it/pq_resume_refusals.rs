#![cfg(not(target_family = "wasm"))]
//! How a sign-in that cannot go ahead is named: an expired resume credential by this client,
//! before it dials, and any refusal of the server's by its error code.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::{code, register, sign_in};
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use std::time::Duration;

    const HOUR: Duration = Duration::from_secs(3_600);

    /// Control: remove `resume::refuse_expired` from `connect`, and the refusal is the dead
    /// server's.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_expired_credential_is_refused_by_name_before_anything_is_sent() {
        citadel_logging::setup_log();
        let pq = pq_settings().pq_sign_in.expect("post-quantum settings");
        let second = ResumePolicy::new(Duration::from_secs(1)).unwrap();
        let misc = ServerMiscSettings {
            pq_sign_in: Some(pq.with_resume(second)),
            ..Default::default()
        };
        let (server, addr, slot) = server(misc, Some(poisoned_argon()), None);
        // The server is stopped mid-test; the client goes on without it.
        let server = async move {
            server.await;
            std::future::pending::<()>().await
        };
        let user = username("expired");
        run(server, move |remote, _| async move {
            let _ = register(&remote, addr, &user, None).await?;
            let asking = SignInFactors::password(PASSWORD).with_resume_lifetime(HOUR);
            let conn = sign_in(&remote, &user, asking).await?;
            let credential = conn.resume.clone().expect("a credential was granted");
            conn.disconnect().await?;
            let server = slot.lock().await.clone().expect("server remote loaded");
            let _ = server.shutdown().await;
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            assert!(credential.expired_at(citadel_user::misc::now_ms()));
            let refused = sign_in(&remote, &user, SignInFactors::resume(credential)).await;
            assert_eq!(code(&refused), Some(ErrorCode::ResumeCredentialExpired));
            remote.shutdown().await
        })
        .await;
    }

    /// Control: send `code: None` in `pq_sign_in::refusal::failure`.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_refused_sign_in_is_named_by_its_code_not_its_text() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("coded");
        run(server, move |remote, _| async move {
            let _ = register(&remote, addr, &user, None).await?;
            let wrong = sign_in(&remote, &user, SignInFactors::password("not the password"));
            assert_eq!(code(&wrong.await), Some(ErrorCode::PqSignInFailed));
            remote.shutdown().await
        })
        .await;
    }
}
