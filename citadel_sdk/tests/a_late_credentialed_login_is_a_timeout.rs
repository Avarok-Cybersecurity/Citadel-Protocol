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
    use crate::common::link::{proxy, saw, Plan, Seen};
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::{tokio, ErrorCode};
    use citadel_proto::constants::LOGIN_EXPIRATION_TIME;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{managed, ManualClock};
    use citadel_sdk::test_common::{server_on, LOCALHOST_STUN_SERVERS};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const PASSWORD: &str = "password";

    /// The proxy forwards the registration and holds the login: only a deadline can end that
    /// login. The account's server address is the proxy's, so the login dials it.
    fn plans() -> Vec<Plan> {
        vec![Plan::Forward, Plan::Hold { release: None }]
    }

    fn backend() -> String {
        let dir = std::env::temp_dir().join(format!("late-login-{}", Uuid::new_v4()));
        dir.to_string_lossy().to_string()
    }

    fn client<K: NetKernel<StackedRatchet> + 'static>(
        kernel: K,
        mode: LinkManagerMode,
        backend: &str,
    ) -> NodeFuture<'static, K> {
        DefaultNodeBuilder::default()
            .with_link_manager(mode)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
            .with_backend(BackendType::Filesystem(backend.to_string()))
            .build(kernel)
            .unwrap()
    }

    /// Registers a new account on `backend`, through `server`, from a node whose clock never
    /// moves, against a server whose clock the test owns, so no deadline can end the registration however slow the host
    /// is. The registration used to race a real deadline: under a stress run, the server's Argon2
    /// alone took 9-12 s of the 20 inside it, and more under S1-REC's (#391).
    async fn register(server: SocketAddr, backend: &str) -> String {
        let username = format!("late_{}", &Uuid::new_v4().to_string()[..8]);
        let name = username.clone();
        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _| async move {
                remote
                    .register_with_defaults(
                        server,
                        name.clone(),
                        name,
                        PASSWORD,
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;
                remote.shutdown().await
            },
        );
        client(kernel, managed(ManualClock::new()), backend)
            .await
            .expect("the registration failed");
        username
    }

    /// Logs `username` in through the proxy, which holds the connection. `cross` crosses the
    /// client's deadline.
    async fn late_login(
        remote: NodeRemote<StackedRatchet>,
        mut seen: tokio::sync::mpsc::UnboundedReceiver<Seen>,
        username: String,
        cross: impl FnOnce(),
        budget: Duration,
    ) -> Result<(), NetworkError> {
        let login = {
            let remote = remote.clone();
            tokio::spawn(async move {
                remote
                    .connect_with_defaults(
                        AuthenticationRequest::credentialed(username, PASSWORD),
                        CertVerification::SelfSignedAccepted,
                    )
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

    /// A late login by a client of `mode`, beside a server whose clock never moves: only the
    /// client's deadline can end it.
    async fn a_late_login(
        mode: LinkManagerMode,
        cross: impl FnOnce() + Send + Sync + 'static,
        budget: Duration,
    ) {
        citadel_logging::setup_log();
        let (server, server_addr) = server_on::<StackedRatchet>(ManualClock::new());
        let backend = backend();
        let run = async move {
            let (proxy_addr, seen) = proxy(server_addr, plans()).await;
            let username = register(proxy_addr, &backend).await;
            let kernel = ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _| {
                    late_login(remote, seen, username, cross, budget)
                },
            );
            client(kernel, mode, &backend).await.map(|_| ())
        };
        // A hang guard, not a latency assertion.
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = run => res,
            }
        })
        .await
        .expect("the test timed out");
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_login_on_a_managed_node_is_a_timeout() {
        let clock = ManualClock::new();
        // Far below the real deadline: an unmanaged timer would not have fired yet.
        let cross = {
            let clock = clock.clone();
            move || clock.advance(LOGIN_EXPIRATION_TIME)
        };
        a_late_login(managed(clock), cross, Duration::from_secs(10)).await
    }

    /// Production's mode: the queue worker's own timer, so this waits the real deadline out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_login_on_a_legacy_node_is_a_timeout() {
        let budget = LOGIN_EXPIRATION_TIME + Duration::from_secs(30);
        a_late_login(LinkManagerMode::Legacy, || {}, budget).await
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
    /// thread). The server, on a thread of its own, ends the login as the client's thread goes
    /// busy, by the test moving its clock across its deadline, and hangs up; when the client's
    /// thread is free again, its own check has not run, and the first thing its session sees is
    /// the server's hang-up.
    #[test]
    fn a_late_login_whose_client_was_starved_is_a_timeout() {
        citadel_logging::setup_log();
        let server_clock = ManualClock::new();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        {
            let server_clock = server_clock.clone();
            on_own_thread(move || async move {
                let (server, server_addr) = server_on::<StackedRatchet>(server_clock);
                addr_tx.send(proxy(server_addr, plans()).await).unwrap();
                let _ = server.await;
            });
        }
        let (proxy_addr, seen) = addr_rx.recv().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        on_own_thread(move || async move {
            let backend = backend();
            let username = register(proxy_addr, &backend).await;
            let kernel = ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _| async move {
                    let starve = move || {
                        let busy = LOGIN_EXPIRATION_TIME - Duration::from_secs(2);
                        async move {
                            tokio::time::sleep(busy).await;
                            server_clock.advance(LOGIN_EXPIRATION_TIME);
                            std::thread::sleep(Duration::from_secs(4));
                        }
                    };
                    let (cross_tx, cross_rx) = tokio::sync::oneshot::channel::<()>();
                    drop(tokio::spawn(async move {
                        if cross_rx.await.is_ok() {
                            starve().await;
                        }
                    }));
                    let cross = move || {
                        let _ = cross_tx.send(());
                    };
                    let budget = LOGIN_EXPIRATION_TIME + Duration::from_secs(30);
                    late_login(remote, seen, username, cross, budget).await
                },
            );
            let res = client(kernel, LinkManagerMode::Legacy, &backend).await;
            done_tx.send(res.map(|_| ())).unwrap();
        });
        let res = match done_rx.recv_timeout(Duration::from_secs(120)) {
            Ok(res) => res,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the test timed out"),
            Err(_) => panic!("the client's thread panicked; its assertion is in the log above"),
        };
        assert!(res.is_ok(), "{res:?}");
    }
}
