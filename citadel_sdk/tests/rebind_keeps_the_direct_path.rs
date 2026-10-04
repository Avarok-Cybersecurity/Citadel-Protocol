//! `rebind_local` moves a direct P2P path's QUIC client to a fresh socket and the path stays up:
//! messages keep flowing both ways, the path cell reports no transition (no fallback to the relay
//! and no new peer connect), and only the dialing side has an endpoint to move.
//!
//! No assertion here is a latency: each is an ordering or an outcome.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const MESSAGES: u32 = 20;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rebound_direct_path_keeps_carrying_messages_with_no_transition() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let finished = Arc::new(AtomicUsize::new(0));
        let rebound = Arc::new(AtomicUsize::new(0));
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
            let rebound = rebound.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    let cell = conn.channel.p2p_path_cell();
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    let mut transitions = cell.subscribe();
                    transitions.mark_unchanged();

                    let report = remote.rebind_local().unwrap();
                    assert!(report.is_complete(), "peer {me}: {report:?}");
                    for moved in &report.rebound {
                        assert_ne!(moved.from.port(), moved.to.port(), "peer {me}");
                    }
                    let _ = rebound.fetch_add(report.rebound.len(), Ordering::SeqCst);
                    wait_for_peers().await;
                    assert_eq!(
                        rebound.load(Ordering::SeqCst),
                        1,
                        "exactly the direct path's QUIC client moves (C2S here is TCP)"
                    );

                    let (mut tx, mut rx) = conn.channel.split();
                    for seq in 0..MESSAGES {
                        tx.send(seq.to_be_bytes().to_vec()).await.unwrap();
                    }
                    for seq in 0..MESSAGES {
                        let msg = rx.next().await.expect("channel closed after the rebind");
                        assert_eq!(msg.as_ref(), seq.to_be_bytes(), "peer {me}");
                    }
                    assert_eq!(cell.get(), P2pPath::Direct, "peer {me}");
                    assert!(
                        !transitions.has_changed().unwrap(),
                        "peer {me}: the path changed after the rebind: {:?}",
                        cell.status()
                    );
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        // A hang guard for the whole pair, not a latency assertion.
        let result = tokio::time::timeout(
            Duration::from_secs(150),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }
}
