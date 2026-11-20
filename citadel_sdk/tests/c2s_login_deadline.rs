//! A login that outlasts its deadline is reported as that timeout (COV-FIX's misreport).
//!
//! The provisional check ends a session still unconnected `LOGIN_EXPIRATION_TIME` after it
//! started. Its end reached the caller as "Queue worker ended unexpectedly", "Session dropped" or
//! "The connection ended before the handshake completed", depending on which of the session's
//! tasks noticed first, so a login that was only slow (a loaded machine, a slow browser's Argon)
//! read as a crash. A managed node reads the deadline from its clock, so the test crosses it at
//! once, with the handshake held at a proxy, instead of waiting 20 seconds for it.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::link::{managed, proxy, saw, ManualClock, Plan, Seen};
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_proto::constants::LOGIN_EXPIRATION_TIME;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, LOCALHOST_STUN_SERVERS};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_login_past_its_deadline_is_reported_as_that_timeout() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let (proxy_addr, mut seen) = proxy(server_addr, vec![Plan::Hold { release: None }]).await;
        let clock = ManualClock::new();
        let clock_for_test = clock.clone();

        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _| async move {
                let login = {
                    let remote = remote.clone();
                    tokio::spawn(async move {
                        remote
                            .connect_with_defaults(
                                AuthenticationRequest::transient(Uuid::new_v4(), proxy_addr),
                                CertVerification::SelfSignedAccepted,
                            )
                            .await
                            .map(|_| ())
                    })
                };
                // The handshake is held: only the deadline can end this login.
                saw(&mut seen, Seen::ClientSpoke(0)).await;
                clock_for_test.advance(LOGIN_EXPIRATION_TIME);
                // Far below the real deadline: an unmanaged timer would not have fired yet.
                let ended = tokio::time::timeout(Duration::from_secs(10), login)
                    .await
                    .expect("the login deadline did not follow the node's clock")
                    .unwrap();
                let err = ended.expect_err("a held login connected").into_string();
                assert!(
                    err.contains("timed out") && err.contains("login deadline"),
                    "the deadline was misreported: {err}"
                );
                remote.shutdown().await
            },
        );
        let mut builder = DefaultNodeBuilder::default();
        let client = builder
            .with_link_manager(managed(clock))
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
            .build(kernel)
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        })
        .await
        .expect("the test timed out");
        assert!(result.is_ok(), "{result:?}");
    }
}
