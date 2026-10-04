#![cfg(not(target_family = "wasm"))]
//! Two accounts on one node sign in to the same server at the same time: two browser windows on
//! one machine, each with its own account, sharing one agent.
//!
//! The client keyed its in-flight (provisional) connections by the server's address alone, so the
//! second account's attempt was refused locally with "Localhost is already trying to connect"
//! while the first was still signing in, every time. The key now names the account too; of two
//! attempts for the same account at once, still only one gets in.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;

    const PASSWORD: &str = "two windows";

    fn sign_in(user: &str) -> AuthenticationRequest {
        AuthenticationRequest::credentialed(user.to_string(), PASSWORD)
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn two_accounts_sign_in_at_once_and_one_account_twice_does_not() {
        citadel_logging::setup_log();
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let client = DefaultNodeBuilder::default()
            .build(GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _: Events| async move {
                    let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
                    let (ra, rb) = tokio::join!(
                        remote.register_with_defaults(addr, a.as_str(), a.as_str(), PASSWORD),
                        remote.register_with_defaults(addr, b.as_str(), b.as_str(), PASSWORD),
                    );
                    ra?;
                    rb?;
                    for round in 0..5 {
                        let (ca, cb) = tokio::join!(
                            remote.connect_with_defaults(sign_in(&a)),
                            remote.connect_with_defaults(sign_in(&b)),
                        );
                        let at = |who: &str, e: NetworkError| {
                            NetworkError::msg(format!("round {round}: {who}: {e}"))
                        };
                        let ca = ca.map_err(|e| at("a", e))?;
                        let cb = cb.map_err(|e| at("b", e))?;
                        ca.disconnect().await?;
                        cb.disconnect().await?;
                    }

                    // The guard still holds for one account: of two simultaneous attempts, exactly
                    // one gets in.
                    let (first, second) = tokio::join!(
                        remote.connect_with_defaults(sign_in(&a)),
                        remote.connect_with_defaults(sign_in(&a)),
                    );
                    let outcomes = [&first, &second]
                        .map(|r| r.as_ref().map(|_| ()).map_err(|e| e.to_string()));
                    assert_eq!(
                        outcomes.iter().filter(|o| o.is_ok()).count(),
                        1,
                        "{outcomes:?}"
                    );
                    remote.shutdown().await
                },
            ))
            .unwrap();
        tokio::select! {
            _ = server => panic!("the server ended first"),
            res = client => { res.unwrap(); }
        }
    }
}
