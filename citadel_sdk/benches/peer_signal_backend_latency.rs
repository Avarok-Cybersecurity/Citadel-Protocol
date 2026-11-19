//! Peer signalling against a slow account backend: K pairs register and connect to each other at
//! once, on a server whose host SQL answers the "is this CID registered?" lookup only after a
//! delay, as a remote database would.
//!
//! The server routes every dial after that lookup. Held under the peer layer's exclusive lock, it
//! serialises every pair's signalling behind one backend round-trip at a time, so the wall time
//! grows with K; resolved before the lock, the pairs' lookups overlap. The bench reports the wall
//! time, how many delayed lookups ran, and the most that were ever in flight together.
//!
//! Requires `localhost-testing` and `multi-threaded`. Local only (never a gate):
//! `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench peer_signal_backend_latency`
//! Env: `BENCH_PAIRS` (default 8), `BENCH_BACKEND_DELAY_MS` (default 25).

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
#[path = "../../citadel_user/tests/common/sqlite_host.rs"]
#[allow(dead_code)] // a shared test helper; this bench uses `in_memory` only
mod sqlite_host;

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    not(target_family = "wasm")
))]
mod imp {
    use crate::sqlite_host::SqliteHost;
    use async_trait::async_trait;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::{
        PeerConnectionKernel, PeerConnectionSetupAggregator,
    };
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, TestBarrier};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    /// The host_sql backend's registration lookup (`citadel_user` host_sql schema).
    const REGISTRATION_LOOKUP: &str = "SELECT cid FROM citadel_cnacs WHERE cid = ?";

    #[derive(Default)]
    struct Lookups {
        seen: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    /// SQLite whose registration lookups take `delay`; every other statement runs at once.
    struct SlowLookups {
        inner: SqliteHost,
        delay: Duration,
        lookups: Arc<Lookups>,
    }

    #[async_trait]
    impl SqlHost for SlowLookups {
        async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
            if statements.iter().any(|s| s.sql == REGISTRATION_LOOKUP) {
                let l = &self.lookups;
                l.seen.fetch_add(1, Ordering::Relaxed);
                let now = l.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                l.max_in_flight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                l.in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            self.inner.execute(statements).await
        }

        fn storage_quota(&self) -> Result<StorageQuota, String> {
            self.inner.storage_quota()
        }
    }

    async fn run_pairs(pairs: usize, delay: Duration) -> (Duration, usize, usize) {
        let nodes = 2 * pairs;
        TestBarrier::reset(nodes);
        let lookups = Arc::new(Lookups::default());
        let host = HostSqlHandle::new(SlowLookups {
            inner: SqliteHost::in_memory(StorageQuota::Unlimited),
            delay,
            lookups: lookups.clone(),
        });
        let (server, server_addr) =
            server_test_node(EmptyKernel::<StackedRatchet>::default(), move |b| {
                let _ = b.with_backend(BackendType::HostSql(host));
            });
        let server = tokio::task::spawn(server);
        let uuids: Vec<Uuid> = (0..nodes).map(|_| Uuid::new_v4()).collect();
        let connected = Arc::new(tokio::sync::Barrier::new(nodes + 1));

        let t0 = Instant::now();
        let mut clients = Vec::with_capacity(nodes);
        for me in 0..nodes {
            let partner = me ^ 1;
            let agg = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[partner])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled)
                .add();
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .with_udp_mode(UdpMode::Disabled)
                    .build()
                    .unwrap();
            let connected = connected.clone();
            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut rx, remote| async move {
                    let conn = rx
                        .recv()
                        .await
                        .ok_or_else(|| NetworkError::msg("peer connection never arrived"))??;
                    connected.wait().await;
                    // Keep the channel until every pair is up: dropping it disconnects the pair.
                    connected.wait().await;
                    drop(conn);
                    remote.shutdown_kernel().await
                });
            clients.push(tokio::task::spawn(
                DefaultNodeBuilder::default()
                    .with_link_manager(LinkManagerMode::Legacy)
                    .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                    .with_max_security_level(
                        citadel_sdk::test_common::localhost_max_security_level(),
                    )
                    .build(kernel)
                    .unwrap(),
            ));
        }
        connected.wait().await;
        let elapsed = t0.elapsed();
        connected.wait().await;
        for client in clients {
            let _ = client.await;
        }
        server.abort();
        let _ = server.await;
        let seen = lookups.seen.load(Ordering::Relaxed);
        assert!(
            seen > 0,
            "no registration lookup was delayed: has its SQL changed?"
        );
        (elapsed, seen, lookups.max_in_flight.load(Ordering::SeqCst))
    }

    fn env(key: &str, fallback: u64) -> u64 {
        std::env::var(key).map_or(fallback, |v| v.parse().expect(key))
    }

    pub fn run() {
        let pairs = env("BENCH_PAIRS", 8) as usize;
        let delay = Duration::from_millis(env("BENCH_BACKEND_DELAY_MS", 25));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (elapsed, seen, max_in_flight) = rt.block_on(run_pairs(pairs, delay));
        println!(
            "[pairs={pairs} lookup delay={}ms] all pairs connected in {} ms | {seen} delayed lookups | at most {max_in_flight} in flight",
            delay.as_millis(),
            elapsed.as_millis(),
        );
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
    eprintln!("peer_signal_backend_latency requires --features localhost-testing,multi-threaded");
}
