//! Relayed packet path: two peers whose server forbids the direct route, so every message and its
//! acknowledgement crosses the server's `check_proxy`, exchange messages both ways at once.
//!
//! Per delivered message it reports what the packet path costs, as counts rather than timings:
//!
//! - StateContainer **write** acquisitions (relayed packets used to take one each on the server);
//! - StateContainer read acquisitions and the mean write acquire-wait;
//! - bytes allocated (a counting global allocator; the sender used to copy every plaintext once
//!   more, only to report it if the send failed).
//!
//! Throughput is printed too, for context only: it is a loopback, one-process figure.
//!
//! Requires `localhost-testing`, `multi-threaded` and `lock-profiling`. Local only (never a gate):
//! `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded,lock-profiling --bench relayed_packet_path`
//! Env: `BENCH_MSGS` (messages per direction), `BENCH_PAYLOADS` (comma list of payload sizes).

#[cfg(all(
    feature = "localhost-testing",
    feature = "multi-threaded",
    feature = "lock-profiling",
    not(feature = "mimalloc"),
    not(target_family = "wasm")
))]
mod imp {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::{
        PeerConnectionKernel, PeerConnectionSetupAggregator,
    };
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, TestBarrier};
    use futures::StreamExt;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    static ALLOCATED: AtomicU64 = AtomicU64::new(0);

    /// The system allocator, counting the bytes it hands out.
    struct Counting;

    // SAFETY: every call forwards to `System` with the caller's layout unchanged; the counter is
    // a relaxed atomic that never influences allocation.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCATED.fetch_add(new_size as u64, Ordering::Relaxed);
            System.realloc(ptr, layout, new_size)
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    /// Every path for every class except the direct one: the pair can only use the server relay.
    fn relay_only_policy() -> PathPolicy {
        let rules = PathKind::ALL
            .into_iter()
            .map(|kind| PathRule {
                kind,
                enabled: kind != PathKind::Direct,
                attempt_timeout: Duration::from_secs(30),
                cost_weight: 1,
                classes: PathClasses::ALL,
            })
            .collect();
        PathPolicy::new(rules, PathClasses::NONE).expect("a valid relay-only policy")
    }

    pub struct Report {
        msgs_per_sec: f64,
        writes_per_msg: f64,
        reads_per_msg: f64,
        avg_write_wait_ns: f64,
        alloc_bytes_per_msg: f64,
    }

    async fn run_pair(msgs: usize, payload_len: usize) -> Report {
        TestBarrier::reset(2);
        let (server, server_addr) =
            server_test_node(EmptyKernel::<StackedRatchet>::default(), |b| {
                let _ = b.with_path_policy(relay_only_policy());
            });
        let server = tokio::task::spawn(server);
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let connected = Arc::new(tokio::sync::Barrier::new(3));
        let done = Arc::new(tokio::sync::Barrier::new(3));
        let received = Arc::new(AtomicU64::new(0));

        let mut clients = Vec::with_capacity(2);
        for me in 0..2 {
            let agg = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled)
                .add();
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .with_udp_mode(UdpMode::Disabled)
                    .build()
                    .unwrap();
            let (connected, done, received) = (connected.clone(), done.clone(), received.clone());
            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut rx, remote| async move {
                    let conn = rx
                        .recv()
                        .await
                        .ok_or_else(|| NetworkError::msg("peer connection never arrived"))??;
                    // Both halves live until the pair is done: dropping a receive half disconnects.
                    let (mut tx, mut rx) = conn.channel.split();
                    connected.wait().await;
                    let sender = async {
                        for _ in 0..msgs {
                            tx.send(vec![0xABu8; payload_len]).await?;
                        }
                        Ok::<_, NetworkError>(())
                    };
                    let receiver = async {
                        let mut stream = (&mut rx).take(msgs);
                        while stream.next().await.is_some() {
                            received.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok::<_, NetworkError>(())
                    };
                    let (sent, got) = futures::future::join(sender, receiver).await;
                    sent?;
                    got?;
                    done.wait().await;
                    drop((tx, rx));
                    remote.shutdown_kernel().await
                });
            clients.push(tokio::task::spawn(
                DefaultNodeBuilder::default()
                    .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                    .build(kernel)
                    .unwrap(),
            ));
        }

        connected.wait().await;
        citadel_proto::lock_profiling::reset();
        let bytes_before = ALLOCATED.load(Ordering::Relaxed);
        let t0 = Instant::now();
        done.wait().await;
        let elapsed = t0.elapsed().as_secs_f64();
        let bytes = ALLOCATED.load(Ordering::Relaxed) - bytes_before;
        let locks = citadel_proto::lock_profiling::snapshot();

        for client in clients {
            let _ = client.await;
        }
        server.abort();
        let _ = server.await;

        let delivered = received.load(Ordering::Relaxed) as f64;
        assert_eq!(delivered as usize, 2 * msgs, "every message must arrive");
        Report {
            msgs_per_sec: delivered / elapsed,
            writes_per_msg: locks.write_count as f64 / delivered,
            reads_per_msg: locks.read_count as f64 / delivered,
            avg_write_wait_ns: locks.avg_write_wait_ns(),
            alloc_bytes_per_msg: bytes as f64 / delivered,
        }
    }

    fn env(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    pub fn run() {
        let msgs: usize = env("BENCH_MSGS").map_or(2000, |v| v.parse().expect("BENCH_MSGS"));
        let payloads: Vec<usize> = env("BENCH_PAYLOADS").map_or(vec![256, 65536], |v| {
            v.split(',')
                .map(|x| x.trim().parse().expect("BENCH_PAYLOADS"))
                .collect()
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        for payload_len in payloads {
            let r = rt.block_on(run_pair(msgs, payload_len));
            println!(
                "[relayed payload={payload_len}B msgs={msgs}x2] writes/msg {:.3} | reads/msg {:.3} | avg write wait {:.0}ns | alloc {:.0} B/msg ({:.2}x payload) | {:.0} msgs/s",
                r.writes_per_msg,
                r.reads_per_msg,
                r.avg_write_wait_ns,
                r.alloc_bytes_per_msg,
                r.alloc_bytes_per_msg / payload_len as f64,
                r.msgs_per_sec,
            );
        }
    }
}

fn main() {
    #[cfg(all(
        feature = "localhost-testing",
        feature = "multi-threaded",
        feature = "lock-profiling",
        not(feature = "mimalloc"),
        not(target_family = "wasm")
    ))]
    imp::run();
    #[cfg(not(all(
        feature = "localhost-testing",
        feature = "multi-threaded",
        feature = "lock-profiling",
        not(feature = "mimalloc"),
        not(target_family = "wasm")
    )))]
    eprintln!(
        "relayed_packet_path requires --features localhost-testing,multi-threaded,lock-profiling (without mimalloc)"
    );
}
