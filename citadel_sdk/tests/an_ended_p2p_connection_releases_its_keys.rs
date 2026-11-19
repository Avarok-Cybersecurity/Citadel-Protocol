//! Once a P2P connection has ended, neither peer keeps its key material.
//!
//! A P2P connection is set up with a session password, and when it ends its ratchet is kept a
//! short while so packets already in flight still open. Both used to stay for the rest of the
//! C2S session, one set per peer ever connected to. After one peer disconnects, each node's
//! footprint must hold its C2S session password only, and the ended connection's ratchet must be
//! gone once its keep window has passed.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// The protocol keeps an ended connection's ratchet for one group window (60 s), then drops
    /// it; the bound adds room for a loaded runner.
    const STALE_RATCHET_GONE_WITHIN: Duration = Duration::from_secs(90);

    /// Polls this node's footprint until `done` holds, failing at the deadline with what it saw.
    async fn until(
        remote: &NodeRemote<StackedRatchet>,
        me: usize,
        what: &str,
        done: impl Fn(&SessionFootprint) -> bool,
    ) {
        let outcome = tokio::time::timeout(STALE_RATCHET_GONE_WITHIN, async {
            while !done(&remote.session_footprint()) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            outcome.is_ok(),
            "peer {me}: {what}: {:?}",
            remote.session_footprint()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_ended_p2p_connection_leaves_no_password_or_ratchet_behind() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let finished = Arc::new(AtomicUsize::new(0));
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();
        for me in 0..2 {
            let setup = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled);
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let finished = finished.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    let node = remote.remote().clone();
                    let connected = node.session_footprint();
                    assert_eq!(
                        connected.session_passwords, 2,
                        "peer {me}: the C2S password and this connection's: {connected:?}"
                    );
                    wait_for_peers().await;
                    if me == 0 {
                        conn.remote.disconnect().await.unwrap();
                    }
                    until(&node, me, "the connection's password was kept", |held| {
                        held.session_passwords == 1
                    })
                    .await;
                    until(
                        &node,
                        me,
                        "the ended connection's ratchet was kept",
                        |held| held.stale_p2p_ratchets == 0,
                    )
                    .await;
                    drop(conn);
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .build(kernel)
                .unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        // A hang guard for the whole pair, not a latency assertion.
        let result = tokio::time::timeout(
            Duration::from_secs(240),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }
}
