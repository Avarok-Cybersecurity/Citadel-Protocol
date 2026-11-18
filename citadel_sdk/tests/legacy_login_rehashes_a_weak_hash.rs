#![cfg(not(target_family = "wasm"))]
//! A legacy (Argon2) login against a hash its server stored below the floor succeeds, and the
//! server, restarted with settings that meet the floor, replaces the hash at that login.

#[cfg(feature = "localhost-testing")]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
mod sqlite_host;

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use crate::common::pq::*;
    use crate::sqlite_host::SqliteHost;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_user::auth::pq::record::KsfParams;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Below the floor: what a node that chose cheap hashing stores.
    fn cheap() -> ArgonDefaultServerSettings {
        ArgonDefaultServerSettings {
            lanes: 1,
            hash_length: 32,
            mem_cost: 1024,
            time_cost: 1,
            secret: vec![],
        }
    }

    /// Exactly the floor (the post-quantum factor's floor reads the same constants).
    fn floor() -> ArgonDefaultServerSettings {
        ArgonDefaultServerSettings {
            lanes: KsfParams::FLOOR.lanes,
            hash_length: 32,
            mem_cost: KsfParams::FLOOR.mem_kib,
            time_cost: KsfParams::FLOOR.iterations,
            secret: vec![],
        }
    }

    /// A legacy-only server listening on `listener`, hashing with `argon`, storing into `backend`.
    fn server_at(
        listener: std::net::TcpListener,
        argon: ArgonDefaultServerSettings,
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
            .with_path_policy(citadel_sdk::test_common::localhost_path_policy())
            .with_underlying_protocol(ServerMode::OrderedReliable(
                NativeOrderedReliableConfig::from_tokio_listener(listener).unwrap(),
            ))
            .with_server_argon_settings(argon)
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

    async fn stored_meets_floor(slot: &Slot, user: &str) -> bool {
        let remote = slot.lock().await.clone().expect("server remote loaded");
        let cnac = remote
            .account_manager()
            .get_client_by_username(user)
            .await
            .unwrap()
            .expect("the server has the account");
        let store = cnac.auth_store();
        let argon = store.argon_container().expect("a legacy account");
        argon.settings().meets_floor()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_legacy_login_replaces_a_hash_stored_below_the_floor() {
        citadel_logging::setup_log();
        let backend = SqliteHost::handle();
        let (first, addr, first_slot) = server_at(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            cheap(),
            backend.clone(),
        );
        let (restarted_tx, restarted_rx) = tokio::sync::oneshot::channel::<Slot>();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stopping = first_slot.clone();
        let servers = async move {
            tokio::select! {
                _ = first => panic!("the first server ended by itself"),
                _ = async {
                    let _ = stop_rx.await;
                    let remote = stopping.lock().await.clone().expect("server remote loaded");
                    let _ = remote.shutdown().await;
                } => {}
            }
            let (second, _, second_slot) = server_at(rebind(addr).await, floor(), backend);
            let _ = restarted_tx.send(second_slot);
            second.await;
            panic!("the restarted server ended by itself");
        };
        let user = username("rehash");
        let client = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _| async move {
                    let _ = remote
                        .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                        .await?;
                    assert!(!stored_meets_floor(&first_slot, &user).await);
                    let _ = stop_tx.send(());
                    let second_slot = restarted_rx.await.expect("the server restarted");

                    let conn = login(&remote, &user, PASSWORD).await?;
                    assert!(conn.rekey().await?.is_some());
                    conn.disconnect().await?;
                    assert!(
                        stored_meets_floor(&second_slot, &user).await,
                        "the below-floor hash was kept"
                    );

                    assert!(login(&remote, &user, "not the password").await.is_err());
                    let again = login(&remote, &user, PASSWORD).await?;
                    assert!(again.rekey().await?.is_some());
                    again.shutdown_kernel().await
                },
            ))
            .unwrap();
        tokio::select! {
            _ = servers => unreachable!(),
            res = client => { res.unwrap(); }
        }
    }
}
