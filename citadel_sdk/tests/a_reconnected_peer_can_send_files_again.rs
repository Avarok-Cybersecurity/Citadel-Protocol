//! After a peer disconnects and connects again, its file offers reach the application.
//!
//! `PeerConnectionKernel` routes a peer's file offers to the connection it made with that peer.
//! It used to keep that route after the peer disconnected, so once the two connected again by
//! other means every offer went to the ended connection, where nobody would read it. Here the
//! peers connect, disconnect and connect again, and the second connection's offer must arrive on
//! the session's own transfer receiver and complete.
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

    /// Upper bounds only: each step completes in well under a second on localhost.
    const STEP: Duration = Duration::from_secs(60);

    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_offer_after_reconnecting_reaches_the_receiver() {
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
                .with_udp_mode(UdpMode::Disabled)
                .add();
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let finished = finished.clone();
            let kernel =
                PeerConnectionKernel::new(settings, setup, move |mut results, remote| async move {
                    let receiver = me == 0;
                    let mut session_files = remote.get_incoming_file_transfer_handle()?;
                    let first = results.recv().await.unwrap()?;
                    let session_cid = first.channel.get_session_cid();
                    let first_remote = first.remote.clone();
                    let (first_tx, mut first_rx) = first.channel.split();
                    wait_for_peers().await;
                    if receiver {
                        // The first connection has ended here once its channel does.
                        assert!(first_rx.next().await.is_none());
                    } else {
                        first_remote.disconnect().await?;
                    }
                    drop((first_tx, first_rx, first_remote));
                    wait_for_peers().await;

                    let again = remote
                        .find_target(session_cid, uuids[1 - me])
                        .await?
                        .connect_to_peer()
                        .await?;
                    wait_for_peers().await;
                    if receiver {
                        let mut offer = tokio::time::timeout(STEP, session_files.recv())
                            .await
                            .expect("the second connection's offer never arrived")
                            .expect("the session's transfer receiver closed");
                        let _ = offer.receive_file().await?;
                    } else {
                        tokio::time::timeout(
                            STEP,
                            again.remote.send_file_with_custom_opts(
                                "../resources/TheBridge.pdf",
                                32 * 1024,
                                TransferType::FileTransfer,
                            ),
                        )
                        .await
                        .expect("the receiver never answered the offer")?;
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    drop(again);
                    remote.shutdown_kernel().await
                });
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
