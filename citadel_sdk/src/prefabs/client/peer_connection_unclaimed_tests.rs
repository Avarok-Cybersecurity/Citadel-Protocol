//! A file offer to a connection that will never take its receiver is declined, so the sender
//! hears an answer instead of waiting on one.

use crate::prefabs::client::peer_connection::PeerConnectionKernel;
use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
use crate::prelude::*;
use crate::test_common::{server_info, wait_for_peers, TestBarrier};
use citadel_io::tokio;
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The decline is sent as the offer arrives; this bound only stops a hang.
const ANSWERED_WITHIN: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn an_offer_to_a_connection_that_gave_up_its_receiver_is_declined() {
    citadel_logging::setup_log();
    TestBarrier::setup(2);
    let declined = Arc::new(AtomicBool::new(false));
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
        let declined = declined.clone();
        let kernel =
            PeerConnectionKernel::new(settings, setup, move |mut results, remote| async move {
                let mut conn = results.recv().await.unwrap()?;
                if me == 1 {
                    // This connection will never read file offers.
                    drop(conn.incoming_object_transfer_handles.take());
                }
                wait_for_peers().await;
                if me == 0 {
                    let sent = tokio::time::timeout(
                        ANSWERED_WITHIN,
                        conn.remote.send_file_with_custom_opts(
                            "../resources/TheBridge.pdf",
                            32 * 1024,
                            TransferType::FileTransfer,
                        ),
                    )
                    .await
                    .expect("the sender is still waiting for an answer");
                    assert!(sent.is_err(), "a declined offer was reported as sent");
                    declined.store(true, Ordering::SeqCst);
                }
                wait_for_peers().await;
                drop(conn);
                remote.shutdown_kernel().await
            });
        let client = DefaultNodeBuilder::default()
            .with_stun_servers(crate::test_common::LOCALHOST_STUN_SERVERS)
            .build(kernel)
            .unwrap();
        kernels.push(async move { client.await.map(|_| ()) });
    }
    let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
    let result = tokio::time::timeout(
        Duration::from_secs(150),
        futures::future::try_select(server, clients),
    )
    .await;
    assert!(result.expect("test timed out").is_ok());
    assert!(declined.load(Ordering::SeqCst));
}
