#![cfg(not(target_family = "wasm"))]
//! Admission after the SERVER restarted: a Durable Object redeployed or a process restarted
//! drops every client's transport and comes back with empty memory, so neither a held session
//! nor the ended-session memory is there to recognise a reconnect's resume token. Within the
//! policy's `resume_grace` the reconnect is still not asked; after it, or with no token, it is.

#[cfg(feature = "localhost-testing")]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
mod sqlite_host;

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::*;
    use crate::common::group::{Events, GroupTestKernel};
    use crate::common::pq::*;
    use crate::sqlite_host::SqliteHost;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A server listening on `listener` storing into `backend`.
    fn server_at(
        listener: std::net::TcpListener,
        misc: ServerMiscSettings,
        backend: HostSqlHandle,
    ) -> (impl Future<Output = ()>, SocketAddr, Slot) {
        let slot: Slot = Default::default();
        let loaded = slot.clone();
        let kernel = GroupTestKernel::new(move |remote: NodeRemote<StackedRatchet>, _: Events| {
            let loaded = loaded.clone();
            async move {
                *loaded.lock().await = Some(remote);
                Ok(())
            }
        });
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let bound = listener.local_addr().unwrap();
        let mut builder = NodeBuilder::<StackedRatchet>::default();
        let _ = builder.with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS);
        let _ = builder
            .with_node_type(NodeType::Server(bound))
            .with_underlying_protocol(ServerMode::OrderedReliable(
                NativeOrderedReliableConfig::from_tokio_listener(listener).unwrap(),
            ))
            .with_server_misc_settings(misc)
            .with_server_argon_settings(poisoned_argon())
            .with_backend(BackendType::HostSql(backend));
        let node = builder.build(kernel).unwrap();
        (async move { node.await.map(|_| ()).unwrap() }, bound, slot)
    }

    /// The stopped server's listener closes as its tasks wind down, not as `shutdown` returns.
    async fn rebind(addr: SocketAddr) -> std::net::TcpListener {
        for _ in 0..400 {
            if let Ok(listener) = std::net::TcpListener::bind(addr) {
                return listener;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the stopped server never released {addr}");
    }

    async fn until_client_lost(remote: &NodeRemote<StackedRatchet>, cid: u64) {
        for _ in 0..400 {
            let held = remote.sessions().await.unwrap().sessions;
            if !held.iter().any(|session| session.cid == cid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the client never saw the server go");
    }

    /// How the first server stops: its node shut down (its sessions end and record that), or
    /// its future dropped mid-flight, as an isolate is torn down, so nothing of it runs again.
    /// Dropping it stops its sessions only where they run on its own task, without
    /// `multi-threaded`.
    #[derive(Copy, Clone)]
    enum Stop {
        Shutdown,
        #[cfg_attr(feature = "multi-threaded", allow(dead_code))]
        Crash,
    }

    /// What the next sign-in after the restart came to: `None` admitted, else the refusal.
    type Outcome = Option<ErrorCode>;

    /// Registers and signs `user` in past the first server's check, restarts the server on the
    /// same storage and address, waits `after_restart`, and returns the restarted server's
    /// policy with the next sign-in of `user` (whose client still holds its resume token) and
    /// then of an account registered alongside it that never signed in (so holds none).
    async fn reconnect_after_restart(
        grace: Duration,
        after_restart: Duration,
        stop: Stop,
    ) -> (Arc<Turnstile>, Outcome, Outcome) {
        citadel_logging::setup_log();
        let backend = SqliteHost::handle();
        let misc = pq_settings();
        let (first, addr, first_slot) = server_at(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            guarded_by(&misc, Arc::new(Turnstile::with_grace(grace))),
            backend.clone(),
        );
        let second_policy = Arc::new(Turnstile::with_grace(grace));
        let second_misc = guarded_by(&misc, second_policy.clone());
        let (restarted_tx, restarted_rx) = tokio::sync::oneshot::channel::<()>();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let servers = async move {
            tokio::select! {
                _ = first => panic!("the first server ended by itself"),
                _ = async {
                    let _ = stop_rx.await;
                    if let Stop::Shutdown = stop {
                        let remote = first_slot.lock().await.clone().expect("server remote loaded");
                        let _ = remote.shutdown().await;
                    }
                } => {}
            }
            let (second, _, _) = server_at(rebind(addr).await, second_misc, backend);
            let _ = restarted_tx.send(());
            second.await;
            panic!("the restarted server ended by itself");
        };
        let outcomes: Arc<Mutex<Vec<Outcome>>> = Default::default();
        let recorded = outcomes.clone();
        let user = username("admrestart");
        let never_signed_in = username("admnotoken");
        let client = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(GroupTestKernel::new(move |remote, _| async move {
                register(&remote, addr, &user, Some(GOOD)).await?;
                register(&remote, addr, &never_signed_in, Some(GOOD)).await?;
                let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
                let cid = sign_in(&remote, &user, factors).await?.cid;
                let _ = stop_tx.send(());
                restarted_rx.await.expect("the server restarted");
                until_client_lost(&remote, cid).await;
                tokio::time::sleep(after_restart).await;
                let resumed = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
                if let Ok(conn) = &resumed {
                    assert_eq!(conn.cid, cid);
                }
                recorded.lock().unwrap().push(code(&resumed));
                let unresumed = SignInFactors::password(PASSWORD);
                let fresh = sign_in(&remote, &never_signed_in, unresumed);
                let fresh = code(&fresh.await);
                recorded.lock().unwrap().push(fresh);
                remote.shutdown().await
            }))
            .unwrap();
        tokio::select! {
            _ = servers => unreachable!(),
            res = client => { res.unwrap(); }
        }
        let outcomes = outcomes.lock().unwrap().clone();
        let [resumed, fresh] = outcomes[..] else {
            panic!("expected two sign-in outcomes, got {outcomes:?}");
        };
        (second_policy, resumed, fresh)
    }

    fn guarded_by(misc: &ServerMiscSettings, policy: Arc<Turnstile>) -> ServerMiscSettings {
        ServerMiscSettings {
            admission: Some(policy),
            ..misc.clone()
        }
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_after_a_server_restart_is_not_asked_within_the_grace() {
        let (policy, resumed, fresh) =
            reconnect_after_restart(Duration::from_secs(900), Duration::ZERO, Stop::Shutdown).await;
        assert_eq!(resumed, None, "the resuming client was asked");
        assert_eq!(fresh, Some(ErrorCode::PqSignInAdmissionRequired));
        assert_eq!(
            policy.asked(),
            ["sign-in"],
            "only the account with no token is asked"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_after_a_server_restart_and_the_grace_is_asked() {
        let grace = Duration::from_secs(1);
        let (policy, resumed, fresh) =
            reconnect_after_restart(grace, grace * 3, Stop::Shutdown).await;
        assert_eq!(resumed, Some(ErrorCode::PqSignInAdmissionRequired));
        assert_eq!(fresh, Some(ErrorCode::PqSignInAdmissionRequired));
        assert_eq!(policy.asked(), ["sign-in", "sign-in"]);
    }

    /// The session was live when its server stopped, so its token was never marked ended.
    #[cfg(not(feature = "multi-threaded"))]
    #[citadel_io::tokio::test]
    async fn a_reconnect_after_a_server_crash_is_not_asked_within_the_grace() {
        let (policy, resumed, fresh) =
            reconnect_after_restart(Duration::from_secs(900), Duration::ZERO, Stop::Crash).await;
        assert_eq!(resumed, None, "the resuming client was asked");
        assert_eq!(fresh, Some(ErrorCode::PqSignInAdmissionRequired));
        assert_eq!(
            policy.asked(),
            ["sign-in"],
            "only the account with no token is asked"
        );
    }

    #[cfg(not(feature = "multi-threaded"))]
    #[citadel_io::tokio::test]
    async fn a_reconnect_after_a_server_crash_and_the_grace_of_its_restart_is_asked() {
        let grace = Duration::from_secs(1);
        let (policy, resumed, _) = reconnect_after_restart(grace, grace * 3, Stop::Crash).await;
        assert_eq!(resumed, Some(ErrorCode::PqSignInAdmissionRequired));
        assert_eq!(policy.asked(), ["sign-in", "sign-in"]);
    }
}
