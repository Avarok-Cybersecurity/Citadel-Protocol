#![cfg(not(target_family = "wasm"))]
//! A login the server refuses can be retried at once.
//!
//! The client used to tell the caller about the refusal (`ConnectFail`) before it released the
//! attempt's provisional slot for the server's address: the slot went only when the session's
//! task wound down afterwards. A caller that retried straight away (a user correcting a mistyped
//! password) could find the slot still taken and be refused locally with "Localhost is already
//! trying to connect", without the server ever seeing the retry. Under load it happened in about
//! one run in eighteen of `pq_sign_in_host_sql`.
//!
//! The race is a window between two tasks, so one attempt rarely shows it; this makes many, each
//! retried the moment the refusal arrives, against both sign-in paths.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;

    const ATTEMPTS: usize = 40;

    async fn refuse_then_retry(misc: ServerMiscSettings) {
        citadel_logging::setup_log();
        let (server, addr, _) = server(misc, None, None);
        let user = username("retry");
        run(server, move |remote, _| async move {
            let _ = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            for attempt in 0..ATTEMPTS {
                let refused = login(&remote, &user, "not the password").await;
                let err = refused.err().expect("a wrong password signed in");
                assert_ne!(
                    err.code,
                    ErrorCode::SessionManagerProvisionalConnectionExists,
                    "attempt {attempt}: the wrong password never reached the server"
                );
                let conn = login(&remote, &user, PASSWORD).await.map_err(|err| {
                    NetworkError::msg(format!("attempt {attempt}: the retry was refused: {err}"))
                })?;
                conn.disconnect().await?;
            }
            remote.shutdown().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_refused_legacy_login_can_be_retried_at_once() {
        refuse_then_retry(ServerMiscSettings::default()).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_refused_post_quantum_login_can_be_retried_at_once() {
        refuse_then_retry(pq_settings()).await;
    }
}
