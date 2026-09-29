#![cfg(not(target_family = "wasm"))]
//! A session the server holds for a client that has already gone yields to that
//! client's authenticated `force_login`, and to nothing else.
//!
//! When a client's end of the link is reset but the server's end stays open (a
//! laptop changing Wi-Fi, sleep and wake), the server keeps the old session and
//! refused every new login for the account with "Session Already Connected"
//! until its keep-alive noticed — up to an hour with the defaults. The client
//! could say `force_login`, and nothing read it.
//!
//! A proxy stands in for the network: `sever` closes every relayed link on the
//! client's side only, and abandons the server's side without a FIN or RST, so
//! the server holds a session nobody is at the other end of.
//!
//! What may displace that session is the security question, so each weaker
//! attempt is shown to leave it alone: a login without `force_login`, a login
//! with `force_login` and the wrong password, and a recorded `force_login`
//! login replayed while the session is live.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::{TcpListener, TcpStream};
    use citadel_io::tokio::sync::{Barrier, Notify};
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::server_info;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const PASSWORD: &str = "password123";
    const SERVER_REFUSAL: &str = "Session Already Connected";
    /// The keep-alive would take up to an hour; the displacement itself waits at most 5s.
    const FORCE_LOGIN_WITHIN: Duration = Duration::from_secs(20);
    /// How long a client may take to notice its own link is gone.
    const LOCAL_TEARDOWN_WITHIN: Duration = Duration::from_secs(30);

    /// What the client has sent on one link, up to [`RECORD_AT_MOST`] bytes.
    type Recording = Arc<citadel_io::Mutex<Vec<u8>>>;

    /// Bounds what the proxy records of each link.
    const RECORD_AT_MOST: usize = 1024 * 1024;

    /// Relays TCP to `upstream`, recording the first [`RECORD_AT_MOST`] bytes the client
    /// sent on each link: all an on-path observer needs to replay a login.
    struct SeveringProxy {
        addr: SocketAddr,
        sever: Arc<Notify>,
        client_streams: Arc<citadel_io::Mutex<Vec<Recording>>>,
    }

    impl SeveringProxy {
        async fn start(upstream: SocketAddr) -> Arc<Self> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = Arc::new(Self {
                addr: listener.local_addr().unwrap(),
                sever: Arc::new(Notify::new()),
                client_streams: Arc::new(citadel_io::Mutex::new(Vec::new())),
            });
            let sever = proxy.sever.clone();
            let client_streams = proxy.client_streams.clone();
            citadel_io::tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let server = TcpStream::connect(upstream).await.unwrap();
                    let recorded = Arc::new(citadel_io::Mutex::new(Vec::new()));
                    client_streams.lock().push(recorded.clone());
                    citadel_io::tokio::spawn(relay(client, server, sever.clone(), recorded));
                }
            });
            proxy
        }

        /// Closes every current link on the client's side and abandons the server's side.
        fn sever(&self) {
            self.sever.notify_waiters();
        }

        /// What the client has sent so far on the most recent link.
        fn last_client_stream(&self) -> Vec<u8> {
            self.client_streams
                .lock()
                .last()
                .expect("no link was relayed")
                .lock()
                .clone()
        }
    }

    async fn relay(client: TcpStream, server: TcpStream, sever: Arc<Notify>, recorded: Recording) {
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let severed = sever.notified();
        let upstream = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                {
                    let mut recorded = recorded.lock();
                    let room = RECORD_AT_MOST.saturating_sub(recorded.len());
                    recorded.extend_from_slice(&buf[..n.min(room)]);
                }
                server_write.write_all(&buf[..n]).await?;
            }
        };
        let downstream = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = server_read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                client_write.write_all(&buf[..n]).await?;
            }
        };
        citadel_io::tokio::select! {
            _ = upstream => return,
            _ = downstream => return,
            _ = severed => {}
        }
        // The client's side closes; the server's side is kept open and never read or
        // written again, so the server sees neither a FIN nor a RST.
        drop((client_read, client_write));
        std::mem::forget((server_read, server_write));
    }

    fn standard(force_login: bool) -> ConnectMode {
        ConnectMode::Standard { force_login }
    }

    async fn connect(
        remote: &NodeRemote<StackedRatchet>,
        username: &str,
        password: &str,
        connect_mode: ConnectMode,
    ) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
        remote
            .connect(
                AuthenticationRequest::credentialed(username.to_string(), password),
                connect_mode,
                Default::default(),
                None,
                Default::default(),
                Default::default(),
            )
            .await
    }

    /// Retries a login without `force_login` until the SERVER refuses it: until then the
    /// client itself is still tearing down its own side of the severed link.
    async fn await_server_refusal(remote: &NodeRemote<StackedRatchet>, username: &str) {
        let deadline = citadel_io::tokio::time::Instant::now() + LOCAL_TEARDOWN_WITHIN;
        loop {
            let err = match connect(remote, username, PASSWORD, standard(false)).await {
                Ok(_) => panic!("a login without force_login displaced the held session"),
                Err(err) => err.into_string(),
            };
            if err.contains(SERVER_REFUSAL) {
                return;
            }
            assert!(
                citadel_io::tokio::time::Instant::now() < deadline,
                "the server never refused; last error: {err}"
            );
            citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Registers the two peers to each other and connects them.
    async fn link_peers(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        peer_username: &str,
    ) -> Result<PeerConnectSuccess<StackedRatchet>, NetworkError> {
        let handle = conn
            .propose_target(conn.cid, peer_username.to_string())
            .await?;
        let _ = handle.register_to_peer().await?;
        handle.connect_to_peer().await
    }

    fn usernames(tag: &str) -> (String, String) {
        let id = &Uuid::new_v4().to_string()[..8];
        (format!("{tag}a_{id}"), format!("{tag}b_{id}"))
    }

    /// What the subject does once the server holds its session and its peer is linked.
    #[derive(Clone, Copy)]
    enum Scenario {
        /// Sever, get refused without force_login, then force_login in.
        ForceLoginAfterSever,
        /// Sever, try force_login with the wrong password, and still be refused.
        WrongPasswordAfterSever,
    }

    /// Subject A reaches the server through the proxy; peer B directly. After the
    /// scenario, B reports whether the server told it A's old session ended.
    async fn run_scenario(scenario: Scenario) -> usize {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let proxy = SeveringProxy::start(server_addr).await;
        let (username_a, username_b) = usernames("ho");

        let connected = Arc::new(Barrier::new(2));
        let linked = Arc::new(Barrier::new(2));
        let settled = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let state_b = Arc::new(NodeState::default());

        let kernel_a = {
            let (connected, linked, settled, done, proxy) = (
                connected.clone(),
                linked.clone(),
                settled.clone(),
                done.clone(),
                proxy.clone(),
            );
            let (username, peer) = (username_a.clone(), username_b.clone());
            ReconnectionTestKernel::new(
                Arc::new(NodeState::default()),
                move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                    remote
                        .register_with_defaults(proxy.addr, &username, &username, PASSWORD)
                        .await?;
                    let first = connect(&remote, &username, PASSWORD, standard(false)).await?;
                    let cid = first.cid;
                    connected.wait().await;
                    let p2p = link_peers(&first, &peer).await?;
                    linked.wait().await;

                    proxy.sever();
                    await_server_refusal(&remote, &username).await;

                    match scenario {
                        Scenario::ForceLoginAfterSever => {
                            let again = citadel_io::tokio::time::timeout(
                                FORCE_LOGIN_WITHIN,
                                connect(&remote, &username, PASSWORD, standard(true)),
                            )
                            .await
                            .expect("force_login did not complete promptly")?;
                            assert_eq!(again.cid, cid, "a re-login keeps the account's CID");
                            settled.wait().await;
                            done.wait().await;
                            drop(p2p);
                            again.shutdown_kernel().await
                        }
                        Scenario::WrongPasswordAfterSever => {
                            let wrong =
                                connect(&remote, &username, "not-the-password", standard(true))
                                    .await;
                            assert!(wrong.is_err(), "a wrong password was admitted");
                            // Had the failed attempt displaced the held session, this would now
                            // succeed.
                            await_server_refusal(&remote, &username).await;
                            settled.wait().await;
                            done.wait().await;
                            drop(p2p);
                            remote.shutdown().await
                        }
                    }
                },
            )
        };

        let kernel_b = {
            let (connected, linked, settled, done) = (
                connected.clone(),
                linked.clone(),
                settled.clone(),
                done.clone(),
            );
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
                    linked.wait().await;
                    settled.wait().await;
                    if matches!(scenario, Scenario::ForceLoginAfterSever) {
                        let deadline =
                            citadel_io::tokio::time::Instant::now() + Duration::from_secs(30);
                        while server_teardown_notices(&state) == 0
                            && citadel_io::tokio::time::Instant::now() < deadline
                        {
                            citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    } else {
                        // Give a wrongly sent signal time to arrive before it is counted.
                        citadel_io::tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    done.wait().await;
                    drop(p2p);
                    conn.shutdown_kernel().await
                },
            )
        };

        let client_a = DefaultNodeBuilder::default().build(kernel_a).unwrap();
        let client_b = DefaultNodeBuilder::default().build(kernel_b).unwrap();
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(180), async move {
            citadel_io::tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = futures::future::try_join(client_a, client_b) => res.map(|_| ()),
            }
        })
        .await
        .expect("the test itself timed out");
        assert!(result.is_ok(), "{result:?}");
        server_teardown_notices(&state_b)
    }

    /// How many times the server told this peer that a session it was linked to was torn
    /// down (the notice `execute_session_with_safe_shutdown` sends each linked peer). The
    /// peer's own "connection lost", from its P2P link dropping when the subject's client
    /// went away, is not counted: the server had no part in it.
    fn server_teardown_notices(state: &NodeState) -> usize {
        state
            .p2p_disconnect_responses
            .lock()
            .unwrap()
            .iter()
            .filter(|response| {
                matches!(response, Some(PeerResponse::Disconnected(reason)) if reason.ends_with("forcibly"))
            })
            .count()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn force_login_displaces_a_half_open_session() {
        let notices = run_scenario(Scenario::ForceLoginAfterSever).await;
        assert_eq!(
            notices, 1,
            "the old session's peer was not told, once, that it ended"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_wrong_password_leaves_the_held_session_alone() {
        let notices = run_scenario(Scenario::WrongPasswordAfterSever).await;
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
