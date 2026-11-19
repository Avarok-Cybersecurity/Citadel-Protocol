#![cfg(not(target_family = "wasm"))]
//! Once a session has ended, neither node holds anything for it.
//!
//! Each cycle ends sessions every way a client can: a graceful disconnect; a login the server
//! refuses mid-handshake; and a link cut on the client's side only, which ends the client's
//! session by its stream and leaves the server's half-open until the client's next login
//! replaces it under the same CID. After the cycles, both nodes' session footprints must return
//! to zero and the runtime's live task count to its baseline. A session still held after it
//! ended, or a task left waiting on one, shows up as a count that stays above it.
//!
//! The task count sees only tasks spawned on the runtime, so it measures under
//! `multi-threaded`; single-threaded nodes run theirs on a `LocalSet`, and there only the
//! footprints measure.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::net::{TcpListener, TcpStream};
    use citadel_io::tokio::sync::Notify;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use std::net::SocketAddr;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use uuid::Uuid;

    const CYCLES: usize = 5;

    /// An ended session is released as soon as its teardown has run, which takes milliseconds;
    /// the bound leaves room for a loaded runner. It must stay below the 20 s login expiry: a
    /// task orphaned by a session wakes on that session's first timer, so a longer wait could
    /// not tell an orphan that happened to end from a task that was released.
    const RELEASED_WITHIN: Duration = Duration::from_secs(10);

    /// Relays TCP to the server. `cut_client_side` drops every relayed link's client half and
    /// keeps its server half open, so the server sees nothing end.
    struct ClientSideCut {
        addr: SocketAddr,
        cut: Arc<Notify>,
    }

    impl ClientSideCut {
        async fn start(upstream: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let cut = Arc::new(Notify::new());
            let cut_for_links = cut.clone();
            drop(tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let server = TcpStream::connect(upstream).await.unwrap();
                    drop(tokio::spawn(relay(client, server, cut_for_links.clone())));
                }
            }));
            Self { addr, cut }
        }

        fn cut_client_side(&self) {
            self.cut.notify_waiters();
        }
    }

    async fn relay(mut client: TcpStream, mut server: TcpStream, cut: Arc<Notify>) {
        let cutting = cut.notified();
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
            _ = cutting => std::mem::forget(server),
        }
    }

    fn live_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    /// Waits until both nodes hold nothing for their sessions and the live task count is back
    /// to `baseline`, failing at the deadline with what is still held.
    async fn released(
        client: &NodeRemote<StackedRatchet>,
        server: &NodeRemote<StackedRatchet>,
        baseline: Option<usize>,
    ) -> Result<usize, NetworkError> {
        let empty = SessionFootprint {
            sessions: 0,
            disconnect_records: 0,
            session_passwords: 0,
            stale_p2p_ratchets: 0,
        };
        let settled = || {
            client.session_footprint() == empty
                && server.session_footprint() == empty
                && baseline.is_none_or(|baseline| live_tasks() <= baseline)
        };
        let outcome = tokio::time::timeout(RELEASED_WITHIN, async {
            while !settled() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        let (client_held, server_held, tasks) = (
            client.session_footprint(),
            server.session_footprint(),
            live_tasks(),
        );
        eprintln!("[footprint] client {client_held:?} | server {server_held:?} | live tasks {tasks} (baseline {baseline:?})");
        outcome.map(|_| tasks).map_err(|_| {
            NetworkError::msg(format!(
                "still held {RELEASED_WITHIN:?} after the sessions ended: client {client_held:?}, server {server_held:?}, live tasks {tasks} (baseline {baseline:?})"
            ))
        })
    }

    /// The client's session ends by its stream once its half of the link is gone.
    async fn until_client_session_ended(
        client: &NodeRemote<StackedRatchet>,
    ) -> Result<(), NetworkError> {
        tokio::time::timeout(RELEASED_WITHIN, async {
            while client.session_footprint().sessions > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| NetworkError::msg("the client's session outlived its cut link"))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn ended_sessions_leave_nothing_behind() {
        citadel_logging::setup_log();

        let server_remote = Arc::new(OnceLock::<NodeRemote<StackedRatchet>>::new());
        let server_remote_for_kernel = server_remote.clone();
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |connection| {
                let _ = server_remote_for_kernel.set(connection.remote.remote().clone());
                async move { Ok(()) }
            },
            |_| {},
        );

        let proxy = Arc::new(ClientSideCut::start(server_addr).await);
        let proxy_addr = proxy.addr;
        let username = format!("rel_{}", &Uuid::new_v4().to_string()[..8]);
        let password = "password123";

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                let login = || AuthenticationRequest::credentialed(username.clone(), password);
                remote
                    .register_with_defaults(
                        proxy_addr,
                        username.as_str(),
                        username.as_str(),
                        password,
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;
                remote
                    .connect_with_defaults(login(), CertVerification::SelfSignedAccepted)
                    .await?
                    .disconnect()
                    .await?;
                let server = server_remote
                    .get()
                    .cloned()
                    .ok_or_else(|| NetworkError::msg("the server never saw a connection"))?;
                // What the two nodes run between sessions, once the first ones are gone.
                let baseline = released(&remote, &server, None).await?;

                for cycle in 0..CYCLES {
                    let connection = remote
                        .connect_with_defaults(login(), CertVerification::SelfSignedAccepted)
                        .await?;
                    connection.disconnect().await?;
                    let refused = remote
                        .connect_with_defaults(
                            AuthenticationRequest::credentialed(
                                username.clone(),
                                "not the password",
                            ),
                            CertVerification::SelfSignedAccepted,
                        )
                        .await;
                    if refused.is_ok() {
                        return Err(NetworkError::msg(format!(
                            "cycle {cycle}: a wrong password was accepted"
                        )));
                    }

                    let cut = remote
                        .connect_with_defaults(login(), CertVerification::SelfSignedAccepted)
                        .await?;
                    proxy.cut_client_side();
                    until_client_session_ended(&remote).await?;
                    drop(cut);
                    remote
                        .connect(
                            login(),
                            ConnectMode::Standard { force_login: true },
                            Default::default(),
                            None,
                            Default::default(),
                            Default::default(),
                            CertVerification::SelfSignedAccepted,
                        )
                        .await?
                        .disconnect()
                        .await?;
                }

                let _ = released(&remote, &server, Some(baseline)).await?;
                remote.shutdown().await
            },
        );

        let client = DefaultNodeBuilder::default()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(client_kernel)
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(180), async move {
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
