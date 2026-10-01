//! A hole punch must survive the peer connection rekeying past the ratchet window while it runs.
//!
//! The channel is usable over the server relay before the punch ends, so the application's
//! traffic rekeys the P2P ratchet while the punch coordinates over that same relay. Each side
//! keeps only the last `MAX_RATCHETS_IN_MEMORY` ratchet versions. The punch's coordination
//! stream used to seal every packet with the ratchet the connection started with; once the
//! connection rekeyed past the window, the receiver no longer held that version and dropped each
//! coordination packet ("Unable to get proper HR"), so the punch on loopback failed and
//! `ensure_direct` reported no direct path.
//!
//! The instrument: a `log::Log` stalls the first hole-punch driver to reach its candidate
//! exchange until the application has rekeyed the connection to twice the window. No sleep sets
//! the order, and the assertion is an outcome: the direct path attaches.
//!
//! Multi-threaded only: the stall parks one worker while the rekeys run on the others. Without
//! `multi-threaded` the protocol runs on a single thread, which the stall would park with it.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing", feature = "multi-threaded"))]
mod tests {
    use citadel_crypt::toolset::MAX_RATCHETS_IN_MEMORY;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock};
    use std::time::Duration;
    use uuid::Uuid;

    /// Emitted by each side's punch driver just before it exchanges address candidates with the
    /// peer over the coordination stream.
    const BEFORE_CANDIDATE_EXCHANGE: &str = "[driver] Local reflexive (srflx) addrs";
    const REKEY_TARGET: u32 = 2 * MAX_RATCHETS_IN_MEMORY as u32;
    /// Guards against a hang only; nothing here is a latency assertion.
    const HANG_GUARD: Duration = Duration::from_secs(150);

    struct StallPunchLogger {
        stalls: AtomicUsize,
        rekeyed: Mutex<bool>,
        rekeyed_cv: Condvar,
    }

    impl StallPunchLogger {
        fn mark_rekeyed(&self) {
            *self.rekeyed.lock().unwrap() = true;
            self.rekeyed_cv.notify_all();
        }

        fn wait_rekeyed(&self) {
            let guard = self.rekeyed.lock().unwrap();
            let (guard, _) = self
                .rekeyed_cv
                .wait_timeout_while(guard, HANG_GUARD, |done| !*done)
                .unwrap();
            assert!(*guard, "the application never finished rekeying");
        }
    }

    impl log::Log for StallPunchLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            let message = record.args().to_string();
            if record.level() <= log::Level::Warn {
                eprintln!("[{}] {}: {message}", record.level(), record.target());
            }
            if message.starts_with(BEFORE_CANDIDATE_EXCHANGE)
                && self.stalls.fetch_add(1, Ordering::SeqCst) == 0
            {
                // Hand this worker's queues to another thread first, so the stall is the punch
                // task's alone and the rekeys it waits for keep running.
                tokio::task::block_in_place(|| self.wait_rekeyed());
            }
        }

        fn flush(&self) {}
    }

    fn logger() -> &'static StallPunchLogger {
        static LOGGER: OnceLock<StallPunchLogger> = OnceLock::new();
        LOGGER.get_or_init(|| StallPunchLogger {
            stalls: AtomicUsize::new(0),
            rekeyed: Mutex::new(false),
            rekeyed_cv: Condvar::new(),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_punch_still_attaches_after_the_connection_rekeys_past_the_window() {
        log::set_logger(logger()).expect("no other logger may be installed");
        log::set_max_level(log::LevelFilter::Info);
        TestBarrier::setup(2);
        let finished = Arc::new(AtomicUsize::new(0));
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();
        for me in 0..2 {
            let setup = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled);
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let finished = finished.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    let cell = conn.channel.p2p_path_cell();
                    if me == 0 {
                        let mut version = 0;
                        while version < REKEY_TARGET {
                            if let Some(v) = conn.remote.rekey().await? {
                                version = v;
                            }
                        }
                        logger().mark_rekeyed();
                    }
                    assert_eq!(
                        cell.ensure_direct().await.unwrap(),
                        P2pPath::Direct,
                        "peer {me}"
                    );
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        let result =
            tokio::time::timeout(HANG_GUARD, futures::future::try_select(server, clients)).await;
        assert_eq!(
            logger().stalls.load(Ordering::SeqCst),
            2,
            "both punch drivers must reach the candidate exchange (the first one stalled), or \
             this run proves nothing",
        );
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }
}
