//! Macro end-to-end benchmark: C2S messaging throughput + latency over the full protocol stack
//! (connect → ratchet handshake → per-message AEAD+serialization on the reliable channel).
//!
//! This is the Phase-0 measurement foundation for the optimization sweep — unlike the criterion
//! micro-benches it is far less sensitive to per-iteration CPU thermal noise (it measures sustained
//! end-to-end work, the metric that actually matters: messages/sec and p50/p99 latency) and is the
//! representative training workload for the PGO/BOLT pipeline (Phase 4).
//!
//! Requires `localhost-testing` (test harness) + `multi-threaded` (realistic server profile, and
//! lets the kernel futures be `Send` so we can run them on a multi-thread runtime).
//!
//! Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench macro_throughput`
//! Env overrides: `BENCH_MSGS` (throughput message count), `BENCH_LAT_ROUNDS` (latency ping-pongs).

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
    use std::time::Instant;
    use uuid::Uuid;

    /// Progress marker that flushes immediately (piped stderr is otherwise fully buffered, so a hang
    /// would swallow all markers). Used only for liveness/diagnosis, not measurement.
    macro_rules! mark {
        ($($a:tt)*) => {{
            use std::io::Write;
            let mut e = std::io::stderr();
            let _ = writeln!(e, $($a)*);
            let _ = e.flush();
        }};
    }

    /// 4 KiB: a representative application message — above the small-control-packet regime, below
    /// the file-transfer scramble path, so it exercises the per-message AEAD+serialization hot path.
    const PAYLOAD: usize = 4096;

    fn env_usize(key: &str, default: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    struct Config {
        name: &'static str,
        enc: EncryptionAlgorithm,
        secrecy: SecrecyMode,
    }

    /// A small matrix covering the HW-accelerated AEAD (AES-GCM), the portable AEAD (ChaCha20), and
    /// both secrecy modes (BestEffort = throughput path, Perfect = per-message rekey path). Broad
    /// coverage doubles as good PGO training.
    const CONFIGS: &[Config] = &[
        Config {
            name: "aes_gcm_256/best_effort",
            enc: EncryptionAlgorithm::AES_GCM_256,
            secrecy: SecrecyMode::BestEffort,
        },
        Config {
            name: "aes_gcm_256/perfect",
            enc: EncryptionAlgorithm::AES_GCM_256,
            secrecy: SecrecyMode::Perfect,
        },
        Config {
            name: "chacha20_poly1305/best_effort",
            enc: EncryptionAlgorithm::ChaCha20Poly_1305,
            secrecy: SecrecyMode::BestEffort,
        },
    ];

    struct Report {
        name: &'static str,
        msgs: usize,
        payload: usize,
        throughput_secs: f64,
        lat_rounds: usize,
        p50_us: f64,
        p99_us: f64,
    }

    fn payload(idx: u64) -> SecBuffer {
        let mut v = vec![0u8; PAYLOAD];
        // Stamp the index so the echo can be sanity-checked without a full checksum.
        v[..8].copy_from_slice(&idx.to_be_bytes());
        v.into()
    }

    /// Server side: echo back exactly `total` messages, then shut down. Using an explicit count
    /// (rather than waiting for the client to close the channel) avoids a teardown deadlock — a
    /// peer-initiated close does not reliably surface as `rx.next() == None` on the other side.
    async fn echo_server<R: Ratchet>(
        mut connection: CitadelClientServerConnection<R>,
        total: usize,
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    ) -> Result<(), NetworkError> {
        mark!("[server] connected; echoing {total}");
        let (mut tx, mut rx) = connection.take_channel().unwrap().split();
        for _ in 0..total {
            match rx.next().await {
                // A failed echo during teardown is expected, not an error — stop cleanly.
                Some(msg) => {
                    if tx.send(msg).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        // Rendezvous before shutting down: guarantees the client has received every echo, so our
        // teardown can't tear the connection out from under the client's last receive.
        barrier.wait().await;
        mark!("[server] echoed all; shutting down");
        // Best-effort: the kernel may already be tearing down ("Queue handler signalled shutdown").
        let _ = connection.shutdown_kernel().await;
        Ok(())
    }

    /// Client side: a pipelined throughput phase (N in flight, send+recv concurrently) then a
    /// serial ping-pong latency phase (1 in flight, measure each RTT).
    async fn client_drive<R: Ratchet>(
        mut connection: CitadelClientServerConnection<R>,
        msgs: usize,
        lat_rounds: usize,
        barrier: std::sync::Arc<tokio::sync::Barrier>,
        out: std::sync::Arc<citadel_io::Mutex<Option<(f64, f64, f64)>>>,
    ) -> Result<(), NetworkError> {
        mark!("[client] connected; throughput phase ({msgs} msgs)");
        let (mut tx, mut rx) = connection.take_channel().unwrap().split();

        // --- Throughput: send `msgs` while concurrently draining `msgs` echoes. ---
        let t0 = Instant::now();
        let sender = async {
            for idx in 0..msgs {
                tx.send(payload(idx as u64)).await?;
            }
            Ok::<_, NetworkError>(tx)
        };
        let receiver = async {
            for _ in 0..msgs {
                let _ = rx.next().await.ok_or_else(|| {
                    NetworkError::msg("channel closed mid-throughput-phase".to_string())
                })?;
            }
            Ok::<_, NetworkError>(rx)
        };
        let (tx_res, rx_res) = futures::future::join(sender, receiver).await;
        let (mut tx, mut rx) = (tx_res?, rx_res?);
        let throughput_secs = t0.elapsed().as_secs_f64();
        mark!("[client] throughput done in {throughput_secs:.3}s; latency phase ({lat_rounds})");

        // --- Latency: serial ping-pong, one message in flight, record each RTT. ---
        let mut rtts = Vec::with_capacity(lat_rounds);
        for idx in 0..lat_rounds {
            let t = Instant::now();
            tx.send(payload(idx as u64)).await?;
            let _ = rx
                .next()
                .await
                .ok_or_else(|| NetworkError::msg("channel closed mid-latency-phase".to_string()))?;
            rtts.push(t.elapsed());
        }
        rtts.sort_unstable();
        let pct = |p: f64| -> f64 {
            if rtts.is_empty() {
                return 0.0;
            }
            let i = ((p * (rtts.len() as f64 - 1.0)).round() as usize).min(rtts.len() - 1);
            rtts[i].as_secs_f64() * 1e6
        };
        *out.lock() = Some((throughput_secs, pct(0.50), pct(0.99)));
        // Rendezvous: tell the server every echo has been received before either side tears down.
        barrier.wait().await;
        mark!("[client] latency done; shutting down");

        // Report is already captured above; shutdown is best-effort (benign teardown error).
        let _ = connection.shutdown_kernel().await;
        Ok(())
    }

    async fn run_config(cfg: &Config, msgs: usize, lat_rounds: usize) -> Report {
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(cfg.secrecy)
            .with_crypto_params(KemAlgorithm::MlKem + cfg.enc)
            .build()
            .unwrap();

        let total = msgs + lat_rounds;
        // Fresh per-config rendezvous shared by both endpoints (the global TEST_BARRIER is single-use,
        // and we run several configs in one process).
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let server_barrier = barrier.clone();
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |connection| echo_server(connection, total, server_barrier.clone()),
            |_| {},
        );

        let result = std::sync::Arc::new(citadel_io::Mutex::new(None));
        let result_c = result.clone();
        let client_barrier = barrier.clone();

        let settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, Uuid::new_v4())
                .with_udp_mode(UdpMode::Disabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(settings, move |connection| {
            client_drive(
                connection,
                msgs,
                lat_rounds,
                client_barrier.clone(),
                result_c.clone(),
            )
        });

        let server = tokio::task::spawn(server);
        let client =
            tokio::task::spawn(DefaultNodeBuilder::default().build(client_kernel).unwrap());
        let (s, c) = futures::future::join(server, client).await;
        // A JoinError = a real task panic (surface it). The inner NodeFuture Err on clean shutdown
        // is the benign "Queue handler signalled shutdown" teardown signal — ignore it; the report
        // was captured before shutdown. A genuinely failed exchange instead leaves `result` empty,
        // which the `expect` below turns into a hard failure.
        let _ = s.expect("server task panicked");
        let _ = c.expect("client task panicked");

        let (throughput_secs, p50_us, p99_us) =
            result.lock().take().expect("client produced no report");
        Report {
            name: cfg.name,
            msgs,
            payload: PAYLOAD,
            throughput_secs,
            lat_rounds,
            p50_us,
            p99_us,
        }
    }

    fn emit(reports: &[Report]) {
        let mut json = String::from("{\n  \"payload_bytes\": ");
        json.push_str(&PAYLOAD.to_string());
        json.push_str(",\n  \"configs\": [\n");
        for (i, r) in reports.iter().enumerate() {
            let msgs_per_sec = r.msgs as f64 / r.throughput_secs;
            let mib_per_sec = (r.msgs * r.payload) as f64 / r.throughput_secs / (1024.0 * 1024.0);
            println!(
                "[{}] {} msgs/s | {:.1} MiB/s | p50 {:.1}us p99 {:.1}us ({} msgs, {} rtts)",
                r.name, msgs_per_sec as u64, mib_per_sec, r.p50_us, r.p99_us, r.msgs, r.lat_rounds
            );
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"msgs_per_sec\": {:.1}, \"mib_per_sec\": {:.2}, \"p50_us\": {:.2}, \"p99_us\": {:.2}}}{}\n",
                r.name,
                msgs_per_sec,
                mib_per_sec,
                r.p50_us,
                r.p99_us,
                if i + 1 < reports.len() { "," } else { "" }
            ));
        }
        json.push_str("  ]\n}\n");
        // Anchor the output at the workspace `bench/` dir (CWD when run under cargo is the package
        // dir, not the workspace root). Surface write failures rather than swallowing them.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../bench");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("macro_results.json");
        match std::fs::write(&path, &json) {
            Ok(()) => println!("wrote {}", path.display()),
            Err(e) => mark!("failed to write {}: {e}", path.display()),
        }
    }

    pub fn run() {
        // Intentionally NO citadel_logging::setup_log(): verbose tracing would dominate the measured
        // wall-clock and corrupt the throughput numbers. Run with RUST_LOG only when debugging.
        let msgs = env_usize("BENCH_MSGS", 10_000);
        let lat_rounds = env_usize("BENCH_LAT_ROUNDS", 1_000);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut reports = Vec::new();
        for cfg in CONFIGS {
            mark!("=== config: {} ===", cfg.name);
            reports.push(rt.block_on(run_config(cfg, msgs, lat_rounds)));
            mark!("=== config done: {} ===", cfg.name);
        }
        emit(&reports);
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
    mark!(
        "macro_throughput requires --features localhost-testing,multi-threaded (native only); skipping"
    );
}
