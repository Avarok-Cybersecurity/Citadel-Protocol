#![cfg(not(target_family = "wasm"))]
//! A connect the server refuses before the client has proved anything reads the same, whether
//! the account it names is unknown to the server or its first packet does not authenticate.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use crate::common::pq::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::oneshot;
    use citadel_sdk::prelude::*;

    fn client<F, Fut>(body: F) -> NodeFuture<'static, GroupTestKernel<F>>
    where
        F: FnOnce(NodeRemote<StackedRatchet>, Events) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), NetworkError>> + Send + 'static,
    {
        DefaultNodeBuilder::default()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(GroupTestKernel::new(body))
            .unwrap()
    }

    /// The server's remote, once its kernel has started; both nodes start together.
    async fn server_remote(slot: &Slot) -> NodeRemote<StackedRatchet> {
        let wait = async {
            loop {
                if let Some(remote) = slot.lock().await.clone() {
                    return remote;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .expect("the server's kernel did not start")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_account_and_a_bad_first_packet_are_refused_alike() {
        citadel_logging::setup_log();
        let (server, addr, slot) = server(Default::default(), None, None);
        let (unknown_user, stale_user) = (username("unknown"), username("stale"));
        let (forgotten_tx, forgotten_rx) = oneshot::channel::<()>();
        let (reregistered_tx, reregistered_rx) = oneshot::channel::<()>();

        // A second client registers `stale_user` again once the server has forgotten the first's.
        let other = {
            let user = stale_user.clone();
            client(move |remote, _| async move {
                forgotten_rx.await.expect("the first client ended");
                let _ = remote
                    .register_with_defaults(
                        addr,
                        user.as_str(),
                        user.as_str(),
                        PASSWORD,
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;
                let _ = reregistered_tx.send(());
                remote.shutdown().await
            })
        };

        let first = client(move |remote, _| async move {
            let server_remote = server_remote(&slot).await;
            let accounts = server_remote.account_manager().clone();
            let mut cids = Vec::new();
            for user in [&unknown_user, &stale_user] {
                let registered = remote
                    .register_with_defaults(
                        addr,
                        user.as_str(),
                        user.as_str(),
                        PASSWORD,
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;
                accounts.delete_client_by_cid(registered.cid).await?;
                cids.push(registered.cid);
            }
            let _ = forgotten_tx.send(());
            reregistered_rx.await.expect("the second client ended");

            // The server holds no account for `unknown_user`, and holds `stale_user` under keys
            // this client does not have.
            let Err(unknown_account) = login(&remote, &unknown_user, PASSWORD).await else {
                panic!("an account the server deleted connected");
            };
            let Err(bad_first_packet) = login(&remote, &stale_user, PASSWORD).await else {
                panic!("a first packet under stale keys connected");
            };

            let (bad, unknown) = (
                bad_first_packet.into_string(),
                unknown_account.into_string(),
            );
            assert_eq!(bad, unknown, "the two refusals read differently");
            for cid in cids {
                assert!(
                    !unknown.contains(&cid.to_string()),
                    "the refusal names the account: {unknown}"
                );
            }
            remote.shutdown().await
        });

        tokio::select! {
            _ = server => panic!("the server ended first"),
            res = async { tokio::join!(first, other) } => {
                let (first, other) = res;
                first.unwrap();
                other.unwrap();
            }
        }
    }
}
