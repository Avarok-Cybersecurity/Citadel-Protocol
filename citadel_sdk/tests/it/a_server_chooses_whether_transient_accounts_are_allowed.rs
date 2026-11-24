#![cfg(not(target_family = "wasm"))]
//! A server chooses whether it admits transient accounts (`NodeBuilder::with_transient_accounts`).
//!
//! A transient account is a session with its own CID that the server never persists and that
//! has no password. A server that allows them gives one to any client that asks; a server that
//! does not refuses the request by name, `ErrorCode::PasswordlessUnsupported`, so the client can
//! tell "this server takes no transient accounts" from every other failure. An ordinary
//! registered account is unaffected either way. Not calling the option keeps them allowed.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use crate::common::pq::{login, run, username, PASSWORD};
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;
    use std::net::SocketAddr;
    use uuid::Uuid;

    /// A server built with `allowed` passed to the option, or without the call when `None`.
    fn server(allowed: Option<bool>) -> (impl std::future::Future<Output = ()>, SocketAddr) {
        let kernel =
            GroupTestKernel::new(|_: NodeRemote<StackedRatchet>, _: Events| async { Ok(()) });
        let (node, addr) = server_test_node(kernel, |builder| {
            if let Some(allowed) = allowed {
                let _ = builder.with_transient_accounts(allowed);
            }
        });
        (async move { node.await.map(|_| ()).unwrap() }, addr)
    }

    async fn transient(
        remote: &NodeRemote<StackedRatchet>,
        addr: SocketAddr,
    ) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
        remote
            .connect_with_defaults(
                AuthenticationRequest::transient(Uuid::new_v4(), addr),
                CertVerification::SelfSignedAccepted,
            )
            .await
    }

    async fn accepts_a_transient_session(allowed: Option<bool>) {
        citadel_logging::setup_log();
        let (server, addr) = server(allowed);
        run(server, move |remote, _| async move {
            let conn = transient(&remote, addr).await?;
            assert_ne!(conn.cid, 0, "a transient session has its own CID");
            conn.disconnect().await?;
            remote.shutdown().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_that_allows_them_gives_a_transient_session_its_own_cid() {
        accepts_a_transient_session(Some(true)).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_built_without_the_option_allows_them() {
        accepts_a_transient_session(None).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_server_that_does_not_refuses_them_by_name_and_still_signs_in_accounts() {
        citadel_logging::setup_log();
        let (server, addr) = server(Some(false));
        run(server, move |remote, _| async move {
            let Err(refused) = transient(&remote, addr).await else {
                panic!("a server that takes no transient accounts gave one");
            };
            assert_eq!(
                refused.code(),
                ErrorCode::PasswordlessUnsupported,
                "the refusal is not named: {refused}"
            );

            let user = username("registered");
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
            assert_ne!(conn.cid, 0);
            conn.disconnect().await?;
            remote.shutdown().await
        })
        .await;
    }
}
