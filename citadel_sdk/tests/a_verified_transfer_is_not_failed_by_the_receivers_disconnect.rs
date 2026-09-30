#![cfg(not(target_family = "wasm"))]
//! A file the receiver stored and verified must not be reported to the sender as failed
//! because the receiver then let go of the peer.
//!
//! The receiver finishes a transfer by queueing its final WAVE_ACK on the direct P2P stream
//! (`inbound_transfer.rs`, `send_with_error_logging` on `preferred_primary_stream`) and then
//! tells its application `ReceptionComplete`. An application that is done with the peer drops
//! its `PeerChannel`, whose `Drop` sends `PeerSignal::Disconnect` the other way: over C2S,
//! through the server (`channel.rs`). Nothing orders the two paths. When the Disconnect is
//! handled on the sender first, the sender removes the vconn -- ending the P2P stream the ack
//! is still in -- and `fail_transfers_with_peer` ends the transfer with
//! `Fail("the peer disconnected")` (or, when the receiver's own teardown closes the link
//! first, "the connection to this peer ended"). The receiver has the whole file; the sender
//! is told it failed. Before `fail_transfers_with_peer` (de3aca85) the same lost ack hung the
//! sender until the 180 s rstest budget instead: CI jobs 99764092618, 100133189342,
//! 106878462162 and 106921384738, where both receivers logged "finished receiving and
//! verifying the file" and the sender's last group then expired.
//!
//! The condition that widens the race is the one the agent suites run under: every node of a
//! node is on one current-thread runtime, and something on that thread does inline CPU work
//! (symbolising a backtrace, ML-KEM keygen, a slow log sink). Here the sender gets its own
//! current-thread runtime and a task on it computes for `BUSY_SLICE` between yields. The
//! sender still makes progress; it just reads its sockets once per slice, so the receiver's
//! final ack and its Disconnect are often both waiting when it next looks, and which one it
//! handles first is no longer decided by which was sent first.
//!
//! Each round is an independent sender/receiver pair, so one run of the test tries the race
//! `ROUNDS` times and fails on the first round that loses it.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, TestBarrier};
    use futures::StreamExt;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    /// How long the sender's thread computes between yields. It is a load, not a bound:
    /// nothing the test asserts depends on it.
    const BUSY_SLICE: Duration = Duration::from_millis(20);
    /// Several groups, so the transfer ends on the same final-ack path every multi-group
    /// transfer ends on, and stays short under the load.
    const FILE_LEN: usize = 256 * 1024;
    const CHUNK: usize = 32 * 1024;
    const ROUNDS: usize = 6;
    /// Only turns a hung sender (the pre-de3aca85 behaviour) into a sentence; far above
    /// anything a passing round needs.
    const SENDER_BUDGET: Duration = Duration::from_secs(120);
    const TEST_BUDGET: Duration = Duration::from_secs(600);

    /// Computes for `BUSY_SLICE`, yields for one scheduler pass, repeats.
    async fn keep_this_runtime_busy() {
        loop {
            let until = Instant::now() + BUSY_SLICE;
            while Instant::now() < until {
                std::hint::spin_loop();
            }
            tokio::task::yield_now().await;
        }
    }

    struct Round {
        /// The receiver stored the whole file and it matched the source.
        receiver_verified: bool,
        /// What `send_file` told the sender.
        sender_outcome: Result<(), String>,
    }

    /// One sender/receiver pair, one transfer. The receiver drops its connection the moment
    /// it sees `ReceptionComplete`, as an application done with the peer does.
    async fn one_round(server_addr: SocketAddr, source: &Path, source_bytes: &[u8]) -> Round {
        let sender_id = Uuid::new_v4();
        let receiver_id = Uuid::new_v4();
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (verified_tx, verified_rx) = tokio::sync::oneshot::channel::<bool>();
        let sender_finished = Arc::new(tokio::sync::Notify::new());

        let receiver_kernel = {
            let sender_finished = sender_finished.clone();
            let source_bytes = source_bytes.to_vec();
            PeerConnectionKernel::new(
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, receiver_id)
                    .build()
                    .unwrap(),
                PeerConnectionSetupAggregator::default()
                    .with_peer_custom(sender_id)
                    .ensure_registered()
                    .with_udp_mode(UdpMode::Disabled)
                    .add(),
                move |mut results, remote| async move {
                    let mut conn = results.recv().await.unwrap()?;
                    let mut handles = conn.get_incoming_file_transfer_handle()?;
                    let mut handle = handles.recv().await.expect("no incoming transfer");
                    handle.accept()?;
                    let mut stored_at = None;
                    while let Some(status) = handle.next().await {
                        match status {
                            ObjectTransferStatus::ReceptionBeginning(path, _) => {
                                stored_at = Some(path)
                            }
                            ObjectTransferStatus::ReceptionComplete => break,
                            ObjectTransferStatus::Fail(reason) => {
                                panic!("the receiver failed the transfer: {reason}")
                            }
                            _ => {}
                        }
                    }
                    drop(handles);
                    drop(conn);

                    let stored = tokio::fs::read(stored_at.expect("no ReceptionBeginning"))
                        .await
                        .unwrap();
                    let _ = verified_tx.send(stored == source_bytes);

                    sender_finished.notified().await;
                    remote.shutdown_kernel().await
                },
            )
        };

        // The sender, alone on a current-thread runtime, so the load is on its thread only.
        let sender_thread = {
            let sender_finished = sender_finished.clone();
            let source = source.to_path_buf();
            std::thread::spawn(move || {
                let kernel = PeerConnectionKernel::new(
                    DefaultServerConnectionSettingsBuilder::transient_with_id(
                        server_addr,
                        sender_id,
                    )
                    .build()
                    .unwrap(),
                    PeerConnectionSetupAggregator::default()
                        .with_peer_custom(receiver_id)
                        .ensure_registered()
                        .with_udp_mode(UdpMode::Disabled)
                        .add(),
                    move |mut results, remote| async move {
                        let conn = results.recv().await.unwrap()?;
                        let load = tokio::spawn(keep_this_runtime_busy());
                        let outcome = tokio::time::timeout(
                            SENDER_BUDGET,
                            conn.remote.send_file_with_custom_opts(
                                source,
                                CHUNK,
                                TransferType::FileTransfer,
                            ),
                        )
                        .await;
                        load.abort();
                        let outcome = match outcome {
                            Ok(result) => result.map_err(|err| err.into_string()),
                            Err(_) => Err(format!(
                                "send_file returned nothing within {SENDER_BUDGET:?}"
                            )),
                        };
                        let _ = outcome_tx.send(outcome);
                        sender_finished.notify_one();
                        drop(conn);
                        remote.shutdown_kernel().await
                    },
                );
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        DefaultNodeBuilder::default()
                            .build(kernel)
                            .unwrap()
                            .await
                            .map(|_| ())
                    })
            })
        };

        let receiver = DefaultNodeBuilder::default()
            .build(receiver_kernel)
            .unwrap();
        receiver.await.expect("the receiver's node failed");
        tokio::task::spawn_blocking(move || sender_thread.join())
            .await
            .unwrap()
            .expect("the sender's thread panicked")
            .expect("the sender's node failed");

        Round {
            receiver_verified: verified_rx.await.unwrap_or(false),
            sender_outcome: outcome_rx
                .await
                .expect("the sender never reported an outcome"),
        }
    }

    fn write_source_file() -> (PathBuf, Vec<u8>) {
        let bytes: Vec<u8> = (0..FILE_LEN).map(|i| (i * 31 + 7) as u8).collect();
        let dir = std::env::temp_dir().join(format!("citadel-final-ack-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        std::fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_verified_transfer_is_not_failed_by_the_receivers_disconnect() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let (source, source_bytes) = write_source_file();
        let (server, server_addr) = server_info::<StackedRatchet>();

        let rounds = async {
            for round in 1..=ROUNDS {
                let Round {
                    receiver_verified,
                    sender_outcome,
                } = one_round(server_addr, &source, &source_bytes).await;
                assert!(
                    receiver_verified,
                    "round {round}: the receiver never verified"
                );
                assert_eq!(
                    sender_outcome,
                    Ok(()),
                    "round {round}/{ROUNDS}: the receiver stored and verified the whole file, \
                     yet the sender was told the transfer failed"
                );
            }
        };
        let result = tokio::time::timeout(TEST_BUDGET, async move {
            tokio::select! {
                res = server => panic!("the server ended first: {:?}", res.map(|_| ())),
                _ = rounds => {}
            }
        })
        .await;
        let _ = std::fs::remove_dir_all(source.parent().unwrap());
        result.expect("the test did not finish");
    }
}
