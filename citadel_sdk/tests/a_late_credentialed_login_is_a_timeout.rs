//! A login by a registered account that outlasts its deadline is reported as that timeout, by
//! code, in both link modes.
//!
//! `c2s_login_deadline` covers a transient login, whose session has no CID. A registered
//! account's session carries its CID from the start, so when the provisional check ended it the
//! session's Drop sent "Session dropped" to the connect's ticket ahead of the timeout, and the
//! caller saw `RemoteDisconnected` (a slow local run, `taskpolicy -b`). Behind it, the timeout
//! itself reached the caller as a bare message with the `Generic` code.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::link::{managed, proxy, saw, with_client, ManualClock, Plan, Seen};
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::{tokio, ErrorCode};
    use citadel_proto::constants::LOGIN_EXPIRATION_TIME;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, LOCALHOST_STUN_SERVERS};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const PASSWORD: &str = "password";

    /// Registers through the proxy's first connection, then logs in through its second, which
    /// the proxy holds: only the deadline can end that login. `cross` crosses the deadline.
    async fn late_login(
        remote: NodeRemote<StackedRatchet>,
        proxy_addr: SocketAddr,
        mut seen: tokio::sync::mpsc::UnboundedReceiver<Seen>,
        cross: impl FnOnce(),
        budget: Duration,
    ) -> Result<(), NetworkError> {
        let username = format!("late_{}", &Uuid::new_v4().to_string()[..8]);
        remote
            .register_with_defaults(proxy_addr, username.clone(), username.clone(), PASSWORD)
            .await?;
        let login = {
            let remote = remote.clone();
            tokio::spawn(async move {
                remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(username, PASSWORD))
                    .await
                    .map(|_| ())
            })
        };
        saw(&mut seen, Seen::ClientSpoke(1)).await;
        cross();
        let ended = tokio::time::timeout(budget, login)
            .await
            .expect("the held login did not end at its deadline")
            .unwrap();
        let err = ended.expect_err("a held login connected");
        assert_eq!(err.code, ErrorCode::Timeout, "misreported as: {err:?}");
        assert!(err.to_string().contains("login deadline"), "{err}");
        remote.shutdown().await
    }

    fn plans() -> Vec<Plan> {
        vec![Plan::Forward, Plan::Hold { release: None }]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_login_on_a_managed_node_is_a_timeout() {
        let clock = ManualClock::new();
        let mode = managed(clock.clone());
        with_client(mode, plans(), move |remote, proxy_addr, seen| {
            // Far below the real deadline: an unmanaged timer would not have fired yet.
            let cross = move || clock.advance(LOGIN_EXPIRATION_TIME);
            late_login(remote, proxy_addr, seen, cross, Duration::from_secs(10))
        })
        .await
    }

    /// Production's mode: the queue worker's own timer, so this waits the real deadline out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_login_on_a_legacy_node_is_a_timeout() {
        with_client(
            LinkManagerMode::Legacy,
            plans(),
            |remote, proxy_addr, seen| {
                let budget = LOGIN_EXPIRATION_TIME + Duration::from_secs(30);
                late_login(remote, proxy_addr, seen, || {}, budget)
            },
        )
        .await
    }

    /// Runs `body` on a thread of its own, the way a node runs: one thread, one `LocalSet`.
    fn on_own_thread<F: std::future::Future + 'static>(body: impl FnOnce() -> F + Send + 'static) {
        drop(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(tokio::task::LocalSet::new().run_until(body()));
        }));
    }

    /// The client's thread is busy across the deadline (a browser hashing Argon on its one
    /// thread). The server, on a thread of its own, ends the login on time and hangs up; when the
    /// client's thread is free again, its own check has not run, and the first thing its session
    /// sees is the server's hang-up.
    #[test]
    fn a_late_login_whose_client_was_starved_is_a_timeout() {
        citadel_logging::setup_log();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        on_own_thread(move || async move {
            let (server, server_addr) = server_info::<StackedRatchet>();
            addr_tx.send(proxy(server_addr, plans()).await).unwrap();
            let _ = server.await;
        });
        let (proxy_addr, seen) = addr_rx.recv().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        on_own_thread(move || async move {
            let kernel = ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _| async move {
                    let starve = || {
                        let busy = LOGIN_EXPIRATION_TIME - Duration::from_secs(2);
                        async move {
                            tokio::time::sleep(busy).await;
                            std::thread::sleep(Duration::from_secs(4));
                        }
                    };
                    let (cross_tx, cross_rx) = tokio::sync::oneshot::channel::<()>();
                    drop(tokio::spawn(async move {
                        if cross_rx.await.is_ok() {
                            starve().await;
                        }
                    }));
                    let cross = move || drop(cross_tx.send(()));
                    let budget = LOGIN_EXPIRATION_TIME + Duration::from_secs(30);
                    let res = late_login(remote, proxy_addr, seen, cross, budget);
                    res.await
                },
            );
            let client = DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .with_stun_servers(LOCALHOST_STUN_SERVERS)
                .build(kernel)
                .unwrap();
            done_tx.send(client.await.map(|_| ())).unwrap();
        });
        let res = match done_rx.recv_timeout(Duration::from_secs(120)) {
            Ok(res) => res,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the test timed out"),
            Err(_) => panic!("the client's thread panicked; its assertion is in the log above"),
        };
        assert!(res.is_ok(), "{res:?}");
    }
}
