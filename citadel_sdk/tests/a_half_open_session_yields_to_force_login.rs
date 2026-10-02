#![cfg(not(target_family = "wasm"))]
//! A session the server holds for a client that has already gone yields to that
//! client's authenticated `force_login`, and to nothing weaker.
//!
//! When a client's end of the link is reset but the server's end stays open (a
//! laptop changing Wi-Fi, sleep and wake), the server keeps the old session and
//! refused every new login for the account with "Session Already Connected"
//! until its keep-alive noticed — up to an hour with the defaults. The client
//! could say `force_login`, and nothing read it.
//!
//! What may displace that session is the security question, so each weaker
//! attempt is shown to leave it alone: a login with `force_login` and the wrong
//! password, and a recorded `force_login` login replayed while the session is live.
//! A reconnect that does not force is covered by
//! `a_half_open_session_yields_to_its_own_reconnect`.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::half_open::{connect, standard, usernames, SeveringProxy, PASSWORD};
    use crate::common::half_open_scenario::{run_scenario, Relogin};
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::TcpStream;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn force_login_displaces_a_half_open_session() {
        let notices = run_scenario(Relogin {
            force_login: true,
            correct_password: true,
        })
        .await;
        assert_eq!(
            notices, 1,
            "the old session's peer was not told, once, that it ended"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_wrong_password_leaves_the_held_session_alone() {
        let notices = run_scenario(Relogin {
            force_login: true,
            correct_password: false,
        })
        .await;
        assert_eq!(
            notices, 0,
            "a login that failed authentication tore the held session down"
        );
    }

    /// A SYN proves only possession of the static device key, and it is replayable. The
    /// recorded client side of a force_login connection, replayed while that connection is
    /// live, must not change the account's session crypto under it.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_replayed_force_login_leaves_a_live_session_working() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let proxy = SeveringProxy::start(server_addr).await;
        let (username, _) = usernames("rp");

        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                remote
                    .register_with_defaults(proxy.addr, &username, &username, PASSWORD)
                    .await?;
                let conn = connect(&remote, &username, PASSWORD, standard(true)).await?;
                conn.rekey().await?;
                let replay = replay_recorded_login(&proxy, server_addr).await;

                for _ in 0..3 {
                    citadel_io::tokio::time::timeout(Duration::from_secs(15), conn.rekey())
                        .await
                        .map_err(|_| {
                            NetworkError::msg("the live session could not rekey after the replay")
                        })??;
                }
                drop(replay);
                conn.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(kernel).unwrap();
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(120), async move {
            citadel_io::tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        })
        .await
        .expect("the test itself timed out");
        assert!(result.is_ok(), "{result:?}");
    }

    /// Replays everything the client sent on its most recent link to the server, on a new
    /// connection, and reads whatever the server answers — as far as an on-path attacker
    /// without keys can go. The connection is returned open.
    async fn replay_recorded_login(proxy: &SeveringProxy, server_addr: SocketAddr) -> TcpStream {
        let recorded = proxy.last_client_stream();
        assert!(!recorded.is_empty(), "nothing was recorded");
        let mut replay = TcpStream::connect(server_addr).await.unwrap();
        replay.write_all(&recorded).await.unwrap();
        let mut answer = vec![0u8; 64 * 1024];
        let _ = citadel_io::tokio::time::timeout(Duration::from_secs(3), replay.read(&mut answer))
            .await;
        replay
    }

    /// The server tracks a live session's requests to peers until they are answered. A
    /// replayed login that goes nowhere must not take them with it when it ends: the
    /// account's peer-layer state belongs to the session that was admitted.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_replayed_force_login_leaves_a_live_sessions_pending_requests_alone() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let proxy = SeveringProxy::start(server_addr).await;
        let (username_a, username_c) = usernames("pr");
        let connected = Arc::new(Barrier::new(2));
        let replayed = Arc::new(Barrier::new(2));

        let kernel_a = {
            let (connected, replayed) = (connected.clone(), replayed.clone());
            let (username, peer) = (username_a.clone(), username_c.clone());
            ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                    remote
                        .register_with_defaults(proxy.addr, &username, &username, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &username, PASSWORD, standard(true)).await?;
                    connected.wait().await;
                    let handle = conn.propose_target(conn.cid, peer).await?;
                    // Post the request, then replay and let the replayed login end.
                    let pending = citadel_io::tokio::time::timeout(
                        Duration::from_secs(40),
                        handle.register_to_peer(),
                    );
                    let replay_and_end = async {
                        citadel_io::tokio::time::sleep(Duration::from_secs(1)).await;
                        drop(replay_recorded_login(&proxy, server_addr).await);
                        // The server's read loop grants a closed stream 2s before ending.
                        citadel_io::tokio::time::sleep(Duration::from_secs(4)).await;
                        replayed.wait().await;
                    };
                    let (registered, ()) = futures::future::join(pending, replay_and_end).await;
                    registered.map_err(|_| {
                        NetworkError::msg("the live session's pending request was lost")
                    })??;
                    conn.shutdown_kernel().await
                },
            )
        };

        let kernel_c = {
            let (username, peer) = (username_c.clone(), username_a.clone());
            ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                    remote
                        .register_with_defaults(server_addr, &username, &username, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &username, PASSWORD, standard(false)).await?;
                    connected.wait().await;
                    replayed.wait().await;
                    let handle = conn.propose_target(conn.cid, peer).await?;
                    let _ = handle.register_to_peer().await?;
                    conn.shutdown_kernel().await
                },
            )
        };

        let client_a = DefaultNodeBuilder::default().build(kernel_a).unwrap();
        let client_c = DefaultNodeBuilder::default().build(kernel_c).unwrap();
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(120), async move {
            citadel_io::tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = futures::future::try_join(client_a, client_c) => res.map(|_| ()),
            }
        })
        .await
        .expect("the test itself timed out");
        assert!(result.is_ok(), "{result:?}");
    }
}
