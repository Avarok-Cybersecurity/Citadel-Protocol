//! UDP media-stream benchmark: the same unreliable-datagram workload (N fragments of
//! `BENCH_MEDIA_FRAG_BYTES`, stamped with send time + sequence) pushed through three transports:
//! (a) Citadel P2P `UdpChannel` (full stack: hole-punched/QUIC UDP + per-datagram ratchet crypto),
//! (b) bare quinn DATAGRAM frames with Citadel's transport config, (c) bare `tokio::net::UdpSocket`.
//! Reports received count, loss %, reorder %, pps, MB/s and p50/p99 one-way latency per arm.
//!
//! Requires `localhost-testing` + `multi-threaded` (native only).
//! Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench udp_media_stream`
//! Env: `BENCH_MEDIA_FRAGS` (20000), `BENCH_MEDIA_RATE_PPS` (0 = unpaced), `BENCH_MEDIA_FRAG_BYTES`
//! (1000 — the live P2P QUIC datagram budget is 1162 B total, i.e. ~1066 B of payload at Standard), `BENCH_RESULTS_DIR` (default `<workspace>/bench`).

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
#[path = "udp_media_stream/arms.rs"]
mod arms;
#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
#[path = "udp_media_stream/workload.rs"]
mod workload;

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
mod imp {
    use crate::arms;
    use crate::workload::{ArmResult, Params, STAMP_LEN};
    use citadel_io::tokio;
    use std::time::Instant;

    fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn emit(p: &Params, results: &[ArmResult]) {
        eprintln!(
            "{:<16} {:>7} {:>7} {:>7} {:>9} {:>10} {:>9} {:>9} {:>9}",
            "arm", "sent", "recv", "loss%", "reorder%", "pps", "MB/s", "p50_us", "p99_us"
        );
        let mut json = format!(
            "{{\n  \"frag_bytes\": {},\n  \"rate_pps\": {},\n  \"arms\": [\n",
            p.frag_bytes, p.rate_pps
        );
        for (i, r) in results.iter().enumerate() {
            eprintln!(
                "{:<16} {:>7} {:>7} {:>7.2} {:>9.2} {:>10.0} {:>9.2} {:>9.1} {:>9.1}",
                r.name,
                r.sent,
                r.received,
                r.loss_pct,
                r.reorder_pct,
                r.pps,
                r.mbps,
                r.p50_us,
                r.p99_us
            );
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"sent\": {}, \"received\": {}, \"loss_pct\": {:.3}, \"reorder_pct\": {:.3}, \"pps\": {:.1}, \"mbps\": {:.3}, \"p50_us\": {:.2}, \"p99_us\": {:.2}}}{}\n",
                r.name, r.sent, r.received, r.loss_pct, r.reorder_pct, r.pps, r.mbps, r.p50_us,
                r.p99_us, if i + 1 < results.len() { "," } else { "" }
            ));
        }
        json.push_str("  ]\n}\n");
        let dir = std::env::var("BENCH_RESULTS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../bench"));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("udp_media_results.json");
        match std::fs::write(&path, &json) {
            Ok(()) => eprintln!("wrote {}", path.display()),
            Err(e) => eprintln!("failed to write {}: {e}", path.display()),
        }
    }

    pub fn run() {
        // No citadel_logging::setup_log(): tracing output would dominate the measured wall-clock.
        let p = Params {
            frags: env_or("BENCH_MEDIA_FRAGS", 20_000),
            rate_pps: env_or("BENCH_MEDIA_RATE_PPS", 0),
            frag_bytes: env_or("BENCH_MEDIA_FRAG_BYTES", 1000),
            epoch: Instant::now(),
        };
        assert!(
            p.frag_bytes >= STAMP_LEN,
            "BENCH_MEDIA_FRAG_BYTES must be >= {STAMP_LEN}"
        );
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        // Hard per-arm budget: connection setup is seconds and the workload is sub-minute at any
        // sane fragment count, so a 120 s overrun means a wedged arm (e.g. a P2P setup race) —
        // fail fast with a clear message instead of hanging the whole bench.
        let budget = std::time::Duration::from_secs(120 + (p.frags / 1_000) as u64);
        let run_arm = |name: &'static str,
                       fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = ArmResult> + '_>,
        >| {
            let r = rt
                .block_on(async { tokio::time::timeout(budget, fut).await })
                .unwrap_or_else(|_| panic!("arm {name} exceeded its {budget:?} budget (wedged)"));
            eprintln!("=== arm done: {name} ===");
            r
        };
        let results = vec![
            run_arm("citadel_udp", Box::pin(arms::citadel(p))),
            run_arm("quinn_datagram", Box::pin(arms::quinn(p))),
            run_arm("raw_udp", Box::pin(arms::raw_udp(p))),
        ];
        emit(&p, &results);
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
    eprintln!(
        "udp_media_stream requires --features localhost-testing,multi-threaded (native only)"
    );
}
