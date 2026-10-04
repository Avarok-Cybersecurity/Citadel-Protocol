#![cfg(not(target_family = "wasm"))]
//! `abandon_session` ends a C2S session here and now, without the server's ack.
//!
//! - A link that died silently leaves the session looking connected, so a new login is refused
//!   locally ("Session for CID .. already exists") until the keep-alive gives up, up to 45
//!   minutes. Abandoning it frees the CID at once, and the next login (no `force_login`) gets the
//!   same CID: its resume token replaces the copy the server still holds.
//! - Abandoning a live session ends it: the server sees its link close, and a linked peer is told.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::half_open::{
        connect, link_peers, server_teardown_notices, standard, usernames, SeveringProxy, PASSWORD,
    };
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::Arc;
    use std::time::Duration;

    const LOCAL_REFUSAL: &str = "already exists. Disconnect first before reconnecting";

    async fn run_clients(
        server: impl std::future::Future<Output = Result<impl Sized, NetworkError>>,
        clients: impl std::future::Future<Output = Result<(), NetworkError>>,
    ) {
        // A hang guard for the whole scenario, not a latency assertion.
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.is_ok()))),
                res = clients => res,
            }
        })
        .await
        .expect("the test itself timed out");
        assert!(result.is_ok(), "{result:?}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_dead_session_frees_its_cid_for_the_next_login() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let proxy = SeveringProxy::start(server_addr).await;
        let (username, _) = usernames("ab");
        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                remote
                    .register_with_defaults(proxy.addr, &username, &username, PASSWORD)
                    .await?;
                let first = connect(&remote, &username, PASSWORD, standard(false)).await?;
                let cid = first.cid;

                proxy.stall();
                let probe = remote.probe_server(cid, Duration::from_secs(2)).await;
                assert!(
                    matches!(probe, ServerProbeOutcome::Timeout),
                    "the stalled link still answers: {probe:?}"
                );
                let refused = match connect(&remote, &username, PASSWORD, standard(false)).await {
                    Ok(_) => panic!("a second session for the CID was admitted"),
                    Err(err) => err,
                };
                assert!(refused.to_string().contains(LOCAL_REFUSAL), "{refused}");

                remote.abandon_session(cid).await?;
                let again = connect(&remote, &username, PASSWORD, standard(false)).await?;
                assert_eq!(again.cid, cid, "a re-login keeps the account's CID");
                assert!(
                    again.rekey().await?.is_some(),
                    "the new session is not usable"
                );
                again.shutdown_kernel().await
            },
        );
        let client = DefaultNodeBuilder::default().build(kernel).unwrap();
        run_clients(server, async move { client.await.map(|_| ()) }).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn abandoning_a_live_session_ends_it_and_its_peer_is_told() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let (username_a, username_b) = usernames("al");
        let (connected, abandoned) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let state_b = Arc::new(NodeState::default());

        let kernel_a = {
            let (connected, abandoned) = (connected.clone(), abandoned.clone());
            let (username, peer) = (username_a.clone(), username_b.clone());
            ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                    remote
                        .register_with_defaults(server_addr, &username, &username, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &username, PASSWORD, standard(false)).await?;
                    let cid = conn.cid;
                    connected.wait().await;
                    let p2p = link_peers(&conn, &peer).await?;

                    remote.abandon_session(cid).await?;
                    let sessions = remote.sessions().await?;
                    assert!(
                        sessions.sessions.iter().all(|s| s.cid != cid),
                        "the abandoned session is still listed: {sessions:?}"
                    );
                    assert!(
                        remote.abandon_session(cid).await.is_err(),
                        "a session was abandoned twice"
                    );
                    abandoned.wait().await;
                    drop(p2p);
                    let again = connect(&remote, &username, PASSWORD, standard(false)).await?;
                    assert_eq!(again.cid, cid);
                    again.shutdown_kernel().await
                },
            )
        };

        let kernel_b = {
            let (connected, abandoned) = (connected.clone(), abandoned.clone());
            let (username, peer) = (username_b.clone(), username_a.clone());
            ReconnectionTestKernel::new(
                state_b.clone(),
                move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| async move {
                    remote
                        .register_with_defaults(server_addr, &username, &username, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &username, PASSWORD, standard(false)).await?;
                    connected.wait().await;
                    let p2p = link_peers(&conn, &peer).await?;
                    // Told by the server once it saw A's link close; bounded by the hang guard.
                    while server_teardown_notices(&state) == 0 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    abandoned.wait().await;
                    drop(p2p);
                    conn.shutdown_kernel().await
                },
            )
        };

        let client_a = DefaultNodeBuilder::default().build(kernel_a).unwrap();
        let client_b = DefaultNodeBuilder::default().build(kernel_b).unwrap();
        run_clients(server, async move {
            futures::future::try_join(client_a, client_b)
                .await
                .map(|_| ())
        })
        .await;
        assert_eq!(server_teardown_notices(&state_b), 1);
    }
}
