//! A login refused because the server holds the account's session says so with a code (S-C8).
//!
//! The server refuses such a login with one fixed reason, and the agent recognised it by
//! matching the string "Session Already Connected" (its `FailureKind::ServerHoldsSession`). The
//! protocol now names that refusal `ErrorCode::RemoteServerHoldsSession`, from its own constant,
//! so a caller matches a code.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::oneshot;
    use citadel_io::ErrorCode;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, LOCALHOST_STUN_SERVERS};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const PASSWORD: &str = "password123";

    /// A client node on `backend`: the two in this test share one, so both hold the account.
    fn client<K: NetKernel<StackedRatchet> + 'static>(
        kernel: K,
        backend: &std::path::Path,
    ) -> NodeFuture<'static, K> {
        DefaultNodeBuilder::default()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .with_backend(BackendType::Filesystem(
                backend.to_string_lossy().to_string(),
            ))
            .build(kernel)
            .unwrap()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_login_refused_for_a_held_session_carries_its_code() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let backend = std::env::temp_dir().join(format!("held-session-{}", Uuid::new_v4()));
        let username = Uuid::new_v4().to_string();
        let (connected, first_is_up) = oneshot::channel::<()>();
        let (refused, second_was_refused) = oneshot::channel::<()>();

        let holder = {
            let username = username.clone();
            ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _| async move {
                    let _ = remote
                        .register_with_defaults(
                            server_addr,
                            &username,
                            &username,
                            PASSWORD,
                            CertVerification::SelfSignedAccepted,
                        )
                        .await?;
                    let _held = remote
                        .connect_with_defaults(
                            AuthenticationRequest::credentialed(username, PASSWORD),
                            CertVerification::SelfSignedAccepted,
                        )
                        .await?;
                    connected.send(()).unwrap();
                    second_was_refused.await.unwrap();
                    remote.shutdown().await
                },
            )
        };
        // The second node shares the account but not the first's resume token, so it cannot
        // prove the held session its own, and it does not force.
        let other = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _| async move {
                let err = remote
                    .connect_with_defaults(
                        AuthenticationRequest::credentialed(username, PASSWORD),
                        CertVerification::SelfSignedAccepted,
                    )
                    .await
                    .map(|_| ())
                    .expect_err("a second client took the held session without forcing");
                assert_eq!(err.code(), ErrorCode::RemoteServerHoldsSession, "{err}");
                refused.send(()).unwrap();
                remote.shutdown().await
            },
        );

        let first = client(holder, &backend);
        let second = async {
            first_is_up.await.unwrap();
            client(other, &backend).await
        };
        let clients = futures::future::try_join(first, second);
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("the test timed out");
        let _ = std::fs::remove_dir_all(&backend);
        assert!(result.is_ok(), "{result:?}");
    }
}
