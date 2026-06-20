//! Multi-session contention bench: drive N concurrent C2S sessions against ONE server and measure
//! aggregate server throughput as N scales. This isolates *server-side* concurrency scaling — the
//! shared `CitadelSessionManager` state across sessions, plus the per-session locks under load.
//!
//! Reading the result: if aggregate msgs/sec scales ~linearly with session count, there is no shared
//! server bottleneck (and a StateContainer lock split would buy little). A plateau/regression as N
//! grows is the signature of contention worth granularizing. This is the measurement that gates the
//! Phase-6 StateContainer work.
//!
//! Requires `localhost-testing` + `multi-threaded`.
//! Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench multi_session_throughput`
//! Env: `BENCH_SESSIONS` (comma list, e.g. "1,4,16,64"), `BENCH_MSGS` (msgs per session).

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
mod imp {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecrecyMode};
    use futures::StreamExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use uuid::Uuid;

    const PAYLOAD: usize = 4096;

    fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn payload() -> SecBuffer {
        vec![0xABu8; PAYLOAD].into()
    }

    /// Server echoes exactly `total` messages then shuts down (explicit count avoids the
    /// peer-close-doesn't-surface-as-None teardown deadlock; same rationale as the macro bench).
    async fn echo_server<R: Ratchet>(
        mut conn: CitadelClientServerConnection<R>,
        total: usize,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> Result<(), NetworkError> {
        let (mut tx, mut rx) = conn.take_channel().unwrap().split();
        for _ in 0..total {
            match rx.next().await {
                Some(msg) => {
                    if tx.send(msg).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        barrier.wait().await;
        let _ = conn.shutdown_kernel().await;
        Ok(())
    }

    /// One client session: pipelined send+recv of `msgs`, counting completed round-trips.
    async fn client_session<R: Ratchet>(
        mut conn: CitadelClientServerConnection<R>,
        msgs: usize,
        barrier: Arc<tokio::sync::Barrier>,
        completed: Arc<AtomicU64>,
    ) -> Result<(), NetworkError> {
        let (mut tx, mut rx) = conn.take_channel().unwrap().split();
        let sender = async {
            for _ in 0..msgs {
                tx.send(payload()).await?;
            }
            Ok::<_, NetworkError>(tx)
        };
        let receiver = async {
            for _ in 0..msgs {
                rx.next()
                    .await
                    .ok_or_else(|| NetworkError::msg("channel closed early".to_string()))?;
            }
            Ok::<_, NetworkError>(rx)
        };
        let (tx_res, rx_res) = futures::future::join(sender, receiver).await;
        let (tx, rx) = (tx_res?, rx_res?);
        completed.fetch_add(msgs as u64, Ordering::Relaxed);
        barrier.wait().await;
        let _ = (tx, rx);
        let _ = conn.shutdown_kernel().await;
        Ok(())
    }

    async fn run_n(sessions: usize, msgs: usize) -> f64 {
        let security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(SecrecyMode::BestEffort)
            .with_crypto_params(KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256)
            .build()
            .unwrap();

        // One barrier party per client + one per matching server connection handler + this task.
        let barrier = Arc::new(tokio::sync::Barrier::new(2 * sessions + 1));
        let completed = Arc::new(AtomicU64::new(0));

        let server_barrier = barrier.clone();
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |conn| echo_server(conn, msgs, server_barrier.clone()),
            |_| {},
        );
        let server = tokio::task::spawn(server);

        let t0 = Instant::now();
        let mut clients = Vec::with_capacity(sessions);
        for _ in 0..sessions {
            let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(
                server_addr,
                Uuid::new_v4(),
            )
            .with_udp_mode(UdpMode::Disabled)
            .with_session_security_settings(security)
            .build()
            .unwrap();
            let cb = barrier.clone();
            let cc = completed.clone();
            let kernel = SingleClientServerConnectionKernel::new(settings, move |conn| {
                client_session(conn, msgs, cb.clone(), cc.clone())
            });
            clients.push(tokio::task::spawn(
                DefaultNodeBuilder::default().build(kernel).unwrap(),
            ));
        }

        // Release everyone once all sessions have finished their exchange.
        barrier.wait().await;
        let elapsed = t0.elapsed().as_secs_f64();

        for c in clients {
            let _ = c.await;
        }
        // The server node shuts itself down after the last handler; do not block on it indefinitely.
        let _ = server.await;

        completed.load(Ordering::Relaxed) as f64 / elapsed
    }

    pub fn run() {
        let sessions: Vec<usize> = std::env::var("BENCH_SESSIONS")
            .ok()
            .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![1, 4, 16, 64]);
        let msgs: usize = env_or("BENCH_MSGS", 2000);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut json = String::from("{\n  \"msgs_per_session\": ");
        json.push_str(&msgs.to_string());
        json.push_str(",\n  \"points\": [\n");
        let mut baseline_per_session = 0.0f64;
        for (i, n) in sessions.iter().enumerate() {
            let mps = rt.block_on(run_n(*n, msgs));
            let per_session = mps / *n as f64;
            if i == 0 {
                baseline_per_session = per_session;
            }
            // Scaling efficiency: per-session throughput vs the single-session baseline. ~1.0 = linear
            // scaling (no shared bottleneck); < 1.0 = contention.
            let eff = if baseline_per_session > 0.0 {
                per_session / baseline_per_session
            } else {
                0.0
            };
            println!(
                "[sessions={}] {:.0} msgs/s aggregate | {:.0}/session | scaling-eff {:.2}",
                n, mps, per_session, eff
            );
            json.push_str(&format!(
                "    {{\"sessions\": {}, \"agg_msgs_per_sec\": {:.1}, \"per_session\": {:.1}, \"scaling_eff\": {:.3}}}{}\n",
                n, mps, per_session, eff,
                if i + 1 < sessions.len() { "," } else { "" }
            ));
        }
        json.push_str("  ]\n}\n");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../bench");
        let _ = std::fs::create_dir_all(&dir);
        match std::fs::write(dir.join("multi_session_results.json"), &json) {
            Ok(()) => println!("wrote bench/multi_session_results.json"),
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
    eprintln!("multi_session_throughput requires --features localhost-testing,multi-threaded");
}
