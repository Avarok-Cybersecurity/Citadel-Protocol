//! Inbound file-transfer contention bench (the **C8 gate**).
//!
//! C8 proposes converting `StateContainer::{inbound_groups, inbound_files}` (`HashMap`) to a `DashMap`,
//! mirroring the landed `outbound_transmitters` fix that eliminated the per-message *outbound* write
//! convoy. The gate question: is the *inbound* group/file path actually contended?
//!
//! Those maps are touched ONLY by object/file transfer (`on_group_header_received` →
//! `inbound_groups.entry`, `on_group_payload_received` → `inbound_files`/`inbound_groups` `get_mut`),
//! each under the StateContainer **write** lock, per packet. Messaging never touches them (it uses the
//! interior-mutable ordered-channel read-lock path), which is why the existing `multi_vconn` bench
//! (messenger channels) shows the lock idle and cannot attribute C8.
//!
//! This bench drives the real path: a **star** of `N` senders each transferring a file to one **hub**
//! node concurrently. The hub's single StateContainer processes all `N` inbound transfers, so if the
//! write lock convoys (like outbound did pre-fix) the avg write acquire-wait balloons with `N`. Under
//! `lock-profiling`, that delta is the C8 gate signal: balloons → convert; flat → skip.
//!
//! Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded,lock-profiling --bench inbound_file_contention`
//! Env: `BENCH_SENDERS` (comma list, e.g. "1,4,8"), `BENCH_FILE_BYTES` (per-transfer file size).

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
mod imp {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::{
        PeerConnectionKernel, PeerConnectionSetupAggregator,
    };
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, TestBarrier};
    use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecrecyMode};
    use citadel_types::proto::{ObjectTransferStatus, TransferType};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Instant;
    use uuid::Uuid;

    fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Write a payload file once; every sender transfers a copy of it to the hub.
    fn make_payload_file(size: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join("citadel_c8_inbound_file_contention.bin");
        std::fs::write(&path, vec![0xCDu8; size]).expect("write temp payload");
        path
    }

    /// Run one star: `senders` nodes each send `file` to the single hub concurrently. Returns the
    /// steady-state wall-clock seconds for the whole fan-in (connection setup excluded).
    async fn run_star(senders: usize, file: &std::path::Path) -> f64 {
        assert!(senders >= 1);
        let peers = senders + 1; // hub + senders
        TestBarrier::reset(peers);

        let security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(SecrecyMode::BestEffort)
            .with_crypto_params(KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256)
            .build()
            .unwrap();

        let (server, server_addr) = server_info::<StackedRatchet>();
        let server = tokio::task::spawn(server);

        let uuids: Vec<Uuid> = (0..peers).map(|_| Uuid::new_v4()).collect();
        let hub = uuids[0];

        let connected = Arc::new(tokio::sync::Barrier::new(peers + 1));
        let done = Arc::new(tokio::sync::Barrier::new(peers + 1));

        let mut clients = Vec::with_capacity(peers);
        for (idx, uuid) in uuids.iter().copied().enumerate() {
            let is_hub = idx == 0;

            // Star topology: hub connects to every sender; each sender connects only to the hub.
            let mut agg = PeerConnectionSetupAggregator::default();
            if is_hub {
                for s in uuids[1..].iter().copied() {
                    agg = agg
                        .with_peer_custom(s)
                        .ensure_registered()
                        .with_udp_mode(UdpMode::Disabled)
                        .with_session_security_settings(security)
                        .add();
                }
            } else {
                agg = agg
                    .with_peer_custom(hub)
                    .ensure_registered()
                    .with_udp_mode(UdpMode::Disabled)
                    .with_session_security_settings(security)
                    .add();
            }

            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .with_udp_mode(UdpMode::Disabled)
                    .with_session_security_settings(security)
                    .build()
                    .unwrap();

            let connected_c = connected.clone();
            let done_c = done.clone();
            let file = file.to_path_buf();
            let expected = if is_hub { senders } else { 1 };

            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut conn_rx, _remote| async move {
                    let mut conns = Vec::with_capacity(expected);
                    for _ in 0..expected {
                        let success = conn_rx
                            .recv()
                            .await
                            .ok_or_else(|| NetworkError::msg("peer conn rx closed early"))??;
                        conns.push(success);
                    }

                    // All star connections established → start the clock.
                    connected_c.wait().await;

                    if is_hub {
                        // Receive a file from every sender CONCURRENTLY — all flow through this one
                        // StateContainer's inbound_groups/inbound_files under its write lock.
                        let recvs = conns.into_iter().map(|mut conn| async move {
                            let mut handles = conn.get_incoming_file_transfer_handle()?;
                            let mut handle = handles
                                .recv()
                                .await
                                .ok_or_else(|| NetworkError::msg("no inbound transfer"))?;
                            handle
                                .accept()
                                .map_err(|e| NetworkError::msg(e.to_string()))?;
                            while let Some(status) = handle.next().await {
                                if matches!(status, ObjectTransferStatus::ReceptionComplete) {
                                    break;
                                }
                            }
                            Ok::<_, NetworkError>(())
                        });
                        futures::future::try_join_all(recvs).await?;
                    } else {
                        // Sender: push the file to the hub.
                        let conn = conns.into_iter().next().unwrap();
                        conn.remote
                            .send_file_with_custom_opts(file, 32 * 1024, TransferType::FileTransfer)
                            .await?;
                    }

                    // Whole fan-in finished → stop the clock before teardown.
                    done_c.wait().await;
                    _remote.shutdown_kernel().await
                });

            clients.push(tokio::task::spawn(
                DefaultNodeBuilder::default().build(kernel).unwrap(),
            ));
        }

        connected.wait().await;
        #[cfg(feature = "lock-profiling")]
        citadel_proto::lock_profiling::reset();
        let t0 = Instant::now();
        done.wait().await;
        let elapsed = t0.elapsed().as_secs_f64();

        #[cfg(feature = "lock-profiling")]
        {
            let s = citadel_proto::lock_profiling::snapshot();
            println!(
                "[senders={}] hub StateContainer lock | writes {} @ avg {:.0}ns wait (total {:.1}ms) | reads {} @ avg {:.0}ns wait",
                senders,
                s.write_count,
                s.avg_write_wait_ns(),
                s.write_wait_nanos as f64 / 1e6,
                s.read_count,
                s.avg_read_wait_ns(),
            );
        }

        for c in clients {
            let _ = c.await;
        }
        server.abort();
        let _ = server.await;

        elapsed
    }

    pub fn run() {
        let sender_counts: Vec<usize> = std::env::var("BENCH_SENDERS")
            .ok()
            .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![1, 4, 8]);
        let file_bytes: usize = env_or("BENCH_FILE_BYTES", 8 * 1024 * 1024);
        let file = make_payload_file(file_bytes);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        println!(
            "inbound file-transfer contention: file {} KiB, senders {:?}",
            file_bytes / 1024,
            sender_counts
        );
        for n in &sender_counts {
            let elapsed = rt.block_on(run_star(*n, &file));
            let agg_mib = (*n as f64 * file_bytes as f64) / (1024.0 * 1024.0) / elapsed.max(1e-9);
            println!(
                "[senders={n}] {n} concurrent transfers in {elapsed:.3}s | {agg_mib:.1} MiB/s aggregate"
            );
        }
        let _ = std::fs::remove_file(&file);
    }
}

fn main() {
    #[cfg(all(
        feature = "localhost-testing",
        feature = "multi-threaded",
        not(target_family = "wasm")
    ))]
    imp::run();
    #[cfg(not(all(
        feature = "localhost-testing",
        feature = "multi-threaded",
        not(target_family = "wasm")
    )))]
    println!("inbound_file_contention requires --features localhost-testing,multi-threaded");
}
