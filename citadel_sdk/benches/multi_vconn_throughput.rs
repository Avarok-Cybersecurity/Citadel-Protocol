//! Multi-vconn contention bench: drive a full **P2P mesh** of K peers so that *each peer's single
//! session* holds K-1 peer virtual connections in **one** `StateContainer`, then have every pair
//! exchange messages simultaneously. This isolates *intra-session* lock contention on the per-session
//! `Arc<RwLock<StateContainerInner>>` — the thing the Phase-6 granularization targets.
//!
//! Why a third bench: `macro_throughput` drives one C2S vconn, and `multi_session_throughput` drives
//! N sessions that each own a *separate* StateContainer — both touch only one vconn per container, so
//! neither sees the lock serialize multiple concurrent vconns. A full mesh does: at mesh size K every
//! node's StateContainer is hit by K-1 concurrent inbound packet streams, all funnelling through the
//! one `inner_mut_state!` guard on the group-packet hot path.
//!
//! Reading the result: `scaling_eff` is per-vconn throughput at mesh size K vs the smallest mesh. ~1.0
//! means adding vconns to a session costs nothing (no intra-session bottleneck → a lock split buys
//! little); a decline as K grows is the contention signature that justifies granularizing the lock.
//!
//! Requires `localhost-testing` + `multi-threaded`.
//! Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench multi_vconn_throughput`
//! Env: `BENCH_MESH_PEERS` (comma list of mesh sizes, e.g. "2,4,6,8"), `BENCH_MSGS` (msgs/vconn/direction).

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
    use futures::StreamExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use uuid::Uuid;

    /// Small payload → maximum packets/sec → maximum lock-acquisition rate → clearest contention
    /// signal (the point is to stress the per-packet `inner_mut_state!` guard, not bulk crypto).
    const PAYLOAD: usize = 256;

    fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn payload() -> SecBuffer {
        vec![0xABu8; PAYLOAD].into()
    }

    /// Run one full mesh of `peers` nodes, each exchanging `msgs` messages per direction with every
    /// other node. Returns `(aggregate_msgs_per_sec, per_vconn_msgs_per_sec)` measured over the
    /// steady-state exchange window only (connection setup is excluded from the timer).
    async fn run_mesh(peers: usize, msgs: usize) -> (f64, f64) {
        assert!(peers >= 2, "a mesh needs at least 2 peers");
        // The prefab's internal `wait_for_peers()` rendezvous is sized to the node count; reset it per
        // config (each mesh size needs a fresh barrier — `setup` would panic on the 2nd config).
        TestBarrier::reset(peers);

        let security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(SecrecyMode::BestEffort)
            .with_crypto_params(KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256)
            .build()
            .unwrap();

        let (server, server_addr) = server_info::<StackedRatchet>();
        let server = tokio::task::spawn(server);

        let uuids: Vec<Uuid> = (0..peers).map(|_| Uuid::new_v4()).collect();

        // Timing rendezvous (peers + this task): the timer starts when every node has established all
        // K-1 channels, and stops when every node has finished its full exchange.
        let connected = Arc::new(tokio::sync::Barrier::new(peers + 1));
        let done = Arc::new(tokio::sync::Barrier::new(peers + 1));
        let received = Arc::new(AtomicU64::new(0));

        let mut clients = Vec::with_capacity(peers);
        for uuid in uuids.iter().copied() {
            let mut agg = PeerConnectionSetupAggregator::default();
            for other in uuids.iter().copied().filter(|u| *u != uuid) {
                agg = agg
                    .with_peer_custom(other)
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
            let received_c = received.clone();
            let expected_channels = peers - 1;

            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut conn_rx, remote| async move {
                    // Collect this node's K-1 peer channels.
                    let mut channels = Vec::with_capacity(expected_channels);
                    for _ in 0..expected_channels {
                        let success = conn_rx.recv().await.ok_or_else(|| {
                            NetworkError::msg("peer conn rx closed early".to_string())
                        })??;
                        channels.push(success.channel);
                    }

                    // All channels up across the whole mesh → start the clock.
                    connected_c.wait().await;

                    // Concurrently pipeline send(msgs)+recv(msgs) on every channel. All of these run
                    // through this node's single StateContainer, so they contend on its one lock.
                    let exchanges = channels.into_iter().map(|chan| {
                        let received_c = received_c.clone();
                        async move {
                            let (mut tx, rx) = chan.split();
                            let sender = async {
                                for _ in 0..msgs {
                                    tx.send(payload()).await?;
                                }
                                Ok::<_, NetworkError>(())
                            };
                            let receiver = async {
                                let mut rx = rx.take(msgs);
                                let mut got = 0u64;
                                while rx.next().await.is_some() {
                                    got += 1;
                                }
                                received_c.fetch_add(got, Ordering::Relaxed);
                                Ok::<_, NetworkError>(())
                            };
                            let (s, r) = futures::future::join(sender, receiver).await;
                            s?;
                            r?;
                            Ok::<_, NetworkError>(())
                        }
                    });
                    futures::future::try_join_all(exchanges).await?;

                    // Whole mesh finished exchanging → stop the clock before anyone tears down.
                    done_c.wait().await;
                    remote.shutdown_kernel().await
                });

            clients.push(tokio::task::spawn(
                DefaultNodeBuilder::default().build(kernel).unwrap(),
            ));
        }

        connected.wait().await;
        // Zero the StateContainer lock counters at the timer start so we measure only the steady-state
        // exchange window (connection setup also takes the lock, but that's outside the timer).
        #[cfg(feature = "lock-profiling")]
        citadel_proto::lock_profiling::reset();
        let t0 = Instant::now();
        done.wait().await;
        let elapsed = t0.elapsed().as_secs_f64();

        // Attribution: if the avg write acquire-wait balloons with mesh size, the throughput ceiling
        // is the per-session StateContainer write lock (convoy); if it stays flat, the ceiling is CPU.
        #[cfg(feature = "lock-profiling")]
        {
            let s = citadel_proto::lock_profiling::snapshot();
            println!(
                "[mesh={}] StateContainer lock | writes {} @ avg {:.0}ns wait (total {:.1}ms) | reads {} @ avg {:.0}ns wait",
                peers,
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

        // Each ordered pair (a -> b) carries `msgs` one-way messages; there are peers*(peers-1) such
        // directed pairs. `received` is the ground-truth count of delivered messages.
        let vconns = (peers * (peers - 1)) as f64;
        let total = received.load(Ordering::Relaxed) as f64;
        let agg = if elapsed > 0.0 { total / elapsed } else { 0.0 };
        (agg, agg / vconns)
    }

    pub fn run() {
        let peer_counts: Vec<usize> = std::env::var("BENCH_MESH_PEERS")
            .ok()
            .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![2, 4, 6, 8]);
        let msgs: usize = env_or("BENCH_MSGS", 500);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut json = String::from("{\n  \"msgs_per_vconn_per_dir\": ");
        json.push_str(&msgs.to_string());
        json.push_str(",\n  \"points\": [\n");
        let mut baseline_per_vconn = 0.0f64;
        for (i, k) in peer_counts.iter().enumerate() {
            let (agg, per_vconn) = rt.block_on(run_mesh(*k, msgs));
            if i == 0 {
                baseline_per_vconn = per_vconn;
            }
            let eff = if baseline_per_vconn > 0.0 {
                per_vconn / baseline_per_vconn
            } else {
                0.0
            };
            let vconns = k * (k - 1);
            println!(
                "[mesh={}] {} vconns/session | {:.0} msgs/s aggregate | {:.0}/vconn | scaling-eff {:.2}",
                k, k - 1, agg, per_vconn, eff
            );
            json.push_str(&format!(
                "    {{\"mesh_peers\": {}, \"vconns_per_session\": {}, \"directed_vconns\": {}, \"agg_msgs_per_sec\": {:.1}, \"per_vconn\": {:.1}, \"scaling_eff\": {:.3}}}{}\n",
                k, k - 1, vconns, agg, per_vconn, eff,
                if i + 1 < peer_counts.len() { "," } else { "" }
            ));
        }
        json.push_str("  ]\n}\n");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../bench");
        let _ = std::fs::create_dir_all(&dir);
        match std::fs::write(dir.join("multi_vconn_results.json"), &json) {
            Ok(()) => println!("wrote bench/multi_vconn_results.json"),
            Err(e) => eprintln!("failed to write results: {e}"),
        }
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
    eprintln!("multi_vconn_throughput requires --features localhost-testing,multi-threaded");
}
