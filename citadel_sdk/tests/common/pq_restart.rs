//! A post-quantum sign-in server that can be stopped and started again on the same address over
//! the same storage, as a redeployed or restarted host is.

use crate::common::group::{Events, GroupTestKernel};
use crate::common::pq::{poisoned_argon, Slot};
use citadel_io::tokio;
use citadel_sdk::prelude::*;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

/// A server listening on `listener` storing into `backend`.
pub fn server_at(
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
    let mut builder = citadel_sdk::test_common::node_builder();
    let _ = builder.with_link_manager(LinkManagerMode::Legacy);
    let _ = builder
        .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level());
    let _ = builder
        .with_node_type(NodeType::Server(bound))
        .with_path_policy(citadel_sdk::test_common::localhost_path_policy())
        .with_server_limits(citadel_sdk::test_common::localhost_server_limits())
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
pub async fn rebind(addr: SocketAddr) -> std::net::TcpListener {
    for _ in 0..400 {
        if let Ok(listener) = std::net::TcpListener::bind(addr) {
            return listener;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the stopped server never released {addr}");
}

pub async fn until_client_lost(remote: &NodeRemote<StackedRatchet>, cid: u64) {
    for _ in 0..400 {
        let held = remote.sessions().await.unwrap().sessions;
        if !held.iter().any(|session| session.cid == cid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the client never saw the server go");
}
