//! A slow C2S hole punch on the server must neither cost the session nor leave
//! UDP one-sided.
//!
//! The server punches (the preconnect STAGE0 handler) while the client's
//! preconnect SUCCESS travels to it. If the server answers BEGIN_CONNECT before
//! its own punch has installed the UDP one-shot, its connect handler hands the
//! application no receiver while the client holds one (#298). If instead it
//! waits for the punch, it waits for up to `MAX_RETRIES` attempts of the
//! puncher's 20 s per-attempt timeout, and `LOGIN_EXPIRATION_TIME` (20 s) ends
//! any session not connected by then: a punch that needed a second attempt
//! cost the whole session.
//!
//! The instrument: the server runs on its own runtime whose worker threads are
//! named, and a `log::Log` stalls the worker that emits the server's
//! `*** ENDING DualStack ***` record (the hole-punch drive task, after
//! consensus, before it hands the socket back) for a chosen time. The session
//! task that runs the SUCCESS handler is a different task and keeps running on
//! another worker.
//!
//! Two stalls. 7 s: the punch still succeeds, but only after the session has
//! connected, so its UDP channel must attach after the connect reply. 25 s:
//! longer than the whole login deadline, and longer than the stalled attempt's
//! own 20 s bound, so the server's punch ends only when its retries run out.
//! The session must survive it, and the server's receiver must resolve rather
//! than wait forever. Each test asserts outcomes only.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_proto::constants::LOGIN_EXPIRATION_TIME;
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info_reactive, wait_for_peers, TestBarrier};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;
    use uuid::Uuid;

    const SERVER_THREAD: &str = "slow-punch-server";
    const PUNCH_END_RECORD: &str = "*** ENDING DualStack ***";

    /// Guards against a hang only; nothing here is a latency assertion.
    const HANG_GUARD: Duration = Duration::from_secs(180);

    struct SlowPunchLogger {
        stall_ms: AtomicU64,
        stalls: AtomicUsize,
    }

    impl log::Log for SlowPunchLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            let on_server = std::thread::current()
                .name()
                .is_some_and(|name| name.starts_with(SERVER_THREAD));
            let message = record.args().to_string();
            if record.level() <= log::Level::Warn {
                eprintln!("[{}] {}: {message}", record.level(), record.target());
            }
            if on_server
                && message == PUNCH_END_RECORD
                && self.stalls.fetch_add(1, Ordering::SeqCst) == 0
            {
                // Hand this worker's queues to another thread first, so the
                // stall is the punch task's alone: without it, a task woken by
                // the punch just before this record sits in this worker's
                // unstealable LIFO slot and is stalled with it.
                let stall = Duration::from_millis(self.stall_ms.load(Ordering::SeqCst));
                tokio::task::block_in_place(|| std::thread::sleep(stall));
            }
        }

        fn flush(&self) {}
    }

    fn logger() -> &'static SlowPunchLogger {
        static LOGGER: OnceLock<SlowPunchLogger> = OnceLock::new();
        LOGGER.get_or_init(|| SlowPunchLogger {
            stall_ms: AtomicU64::new(0),
            stalls: AtomicUsize::new(0),
        })
    }

    fn runtime(name: &'static str) -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name(name)
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Whether this side's UDP receiver delivered a channel. `None`: no receiver.
    async fn udp_delivered<R: Ratchet>(
        rx: Option<tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
    ) -> Option<bool> {
        let rx = rx?;
        Some(
            tokio::time::timeout(HANG_GUARD, rx)
                .await
                .expect("a UDP receiver was handed out and never resolved")
                .is_ok(),
        )
    }

    /// Returns (client, server): whether each side's UDP receiver delivered a
    /// channel, `None` if it had no receiver. Panics unless both sides connected.
    fn connect_with_server_punch_stalled_for(
        punch_stall: Duration,
    ) -> (Option<bool>, Option<bool>) {
        log::set_logger(logger()).expect("no other logger may be installed");
        log::set_max_level(log::LevelFilter::Trace);
        logger()
            .stall_ms
            .store(punch_stall.as_millis() as u64, Ordering::SeqCst);
        TestBarrier::setup(2);

        let server_udp: &OnceLock<Option<bool>> = &OnceLock::new();
        let client_udp: &OnceLock<Option<bool>> = &OnceLock::new();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(move || {
                runtime(SERVER_THREAD).block_on(async move {
                    let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
                        |mut connection| async move {
                            let delivered = udp_delivered(connection.udp_channel_rx.take()).await;
                            let _ = server_udp.set(delivered);
                            wait_for_peers().await;
                            connection.shutdown_kernel().await
                        },
                        |_| {},
                    );
                    addr_tx.send(server_addr).unwrap();
                    tokio::time::timeout(HANG_GUARD, server)
                        .await
                        .expect("server hung")
                        .expect("server failed");
                });
            });

            let server_addr = addr_rx.recv().expect("server address");
            runtime("slow-punch-client").block_on(async move {
                let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(
                    server_addr,
                    Uuid::new_v4(),
                )
                .with_udp_mode(UdpMode::Enabled)
                .build()
                .unwrap();
                let client_kernel = SingleClientServerConnectionKernel::new(
                    settings,
                    |mut connection| async move {
                        let delivered = udp_delivered(connection.udp_channel_rx.take()).await;
                        let _ = client_udp.set(delivered);
                        wait_for_peers().await;
                        connection.shutdown_kernel().await
                    },
                );
                let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
                tokio::time::timeout(HANG_GUARD, client)
                    .await
                    .expect("client hung")
                    .expect("client failed");
            });
        });

        assert_eq!(
            logger().stalls.load(Ordering::SeqCst),
            1,
            "the server's hole punch never reached `{PUNCH_END_RECORD}`, so nothing was stalled \
             and this run proves nothing",
        );
        let server = *server_udp
            .get()
            .expect("the server never saw a connected session");
        let client = *client_udp.get().expect("the client never connected");
        (client, server)
    }

    /// Late, but inside the login deadline, and successful: the server's channel
    /// attaches after the connect reply.
    #[test]
    fn a_punch_that_resolves_after_connect_attaches_udp_on_both_sides() {
        let stall = Duration::from_secs(7);
        assert_eq!(
            connect_with_server_punch_stalled_for(stall),
            (Some(true), Some(true)),
            "after a server punch stalled for {stall:?}, UDP must be delivered on both sides \
             (None: no receiver, Some(false): the receiver closed without a channel)",
        );
    }

    /// A punch that outlasts the whole login deadline must not end the session,
    /// and the server's receiver must resolve once the punch gives up.
    #[test]
    fn a_punch_that_outlasts_the_login_deadline_does_not_end_the_session() {
        let stall = LOGIN_EXPIRATION_TIME + Duration::from_secs(5);
        let (client, server) = connect_with_server_punch_stalled_for(stall);
        assert_eq!(client, Some(true), "the client's own punch succeeded");
        assert!(
            server.is_some(),
            "the server connected before its punch resolved, so it must hold a receiver that \
             the punch's outcome resolves",
        );
    }
}
