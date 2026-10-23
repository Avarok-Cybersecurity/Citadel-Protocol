#![cfg(not(target_family = "wasm"))]
//! A pair that dials each other at the same time must keep the UDP channel of the connection it
//! ends up with, on BOTH ends.
//!
//! The workspace dials every peer as soon as registration answers and auto-accepts every request,
//! so in a call each pair dials in both directions. When the two dials land in the losing order --
//! the second one reaches the server after the first has been accepted -- the server forges the
//! pair twice and both peers run a second key exchange for a connection that is already live. That
//! exchange used to overwrite the live connection's key-exchange state, which holds the sender of
//! its UDP channel offer: the offer was dropped, the agent read it as "this connection will never
//! carry UDP", and every call on the pair failed (CI run 39177756618, `MediaSessionFailed` on one
//! leg only, `Inserted a virtual connection. but overwrote one` x2 on the server).
//!
//! The instrument forces that order: a `log::Log` stalls each peer's hole punch on its
//! `~!@ P2P UDP Hole-punch finished` record (before the UDP channel is handed over) for a few
//! seconds, and the second dial is made as soon as the first connection exists, inside that
//! window. The assertions are outcomes only: the first connection's UDP offer is kept, on both
//! ends, and the second dial is answered (refused) instead of being left to time out.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const PUNCH_RECORD: &str = "~!@ P2P UDP Hole-punch finished";
    /// Long enough for the second dial's exchange to complete before any punch hands over UDP.
    const PUNCH_STALL: Duration = Duration::from_secs(4);
    const DEADLINE: Duration = Duration::from_secs(60);

    struct StallingLogger {
        stalls: AtomicUsize,
    }

    impl log::Log for StallingLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            let message = record.args().to_string();
            if record.level() <= log::Level::Info {
                eprintln!("[{}] {}: {message}", record.level(), record.target());
            }
            // The first connection's two punches; later ones are not stalled.
            if message.starts_with(PUNCH_RECORD) && self.stalls.fetch_add(1, Ordering::SeqCst) < 2 {
                // Blocks the punching task's thread; the node's other work runs elsewhere or
                // waits, and either way the second dial is ordered before this UDP hand-over.
                std::thread::sleep(PUNCH_STALL);
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: StallingLogger = StallingLogger {
        stalls: AtomicUsize::new(0),
    };

    type UdpOffer = Option<tokio::sync::oneshot::Receiver<UdpChannel<StackedRatchet>>>;

    /// Accepts the next connection request that reaches the kernel and returns the channel the
    /// accept created, skipping every other event.
    async fn accept_next(
        events: &mut Events,
        remote: &NodeRemote<StackedRatchet>,
    ) -> Option<(PeerChannel<StackedRatchet>, UdpOffer)> {
        while let Some(event) = events.recv().await {
            match event {
                NodeResult::PeerEvent(PeerEvent {
                    event:
                        signal @ PeerSignal::PostConnect {
                            invitee_response: None,
                            ..
                        },
                    ..
                }) => {
                    responses::peer_connect(signal, true, remote, None)
                        .await
                        .expect("accept sent");
                }
                NodeResult::PeerChannelCreated(created) => {
                    return Some((*created.channel, created.udp_rx_opt));
                }
                _ => {}
            }
        }
        None
    }

    /// Accepts every connection request until the stream ends.
    async fn accept_all(mut events: Events, remote: NodeRemote<StackedRatchet>) {
        while accept_next(&mut events, &remote).await.is_some() {}
    }

    async fn expect_udp(who: &str, offer: UdpOffer) -> UdpChannel<StackedRatchet> {
        let rx = offer.unwrap_or_else(|| panic!("{who}: no UDP channel was offered"));
        match tokio::time::timeout(DEADLINE, rx).await {
            Ok(Ok(channel)) => channel,
            Ok(Err(_)) => panic!("{who}: the live connection withdrew its UDP channel offer"),
            Err(_) => panic!("{who}: no UDP channel within {DEADLINE:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_second_dial_for_a_live_pair_keeps_its_udp_offer_on_both_ends() {
        log::set_logger(&LOGGER).expect("no other logger may be installed");
        log::set_max_level(log::LevelFilter::Trace);
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (dialer, acceptor) = (format!("dialer_{tag}"), format!("acceptor_{tag}"));

        // Dials first; accepts the peer's later dial.
        let (me, peer) = (dialer.clone(), acceptor.clone());
        let dialer_node = GroupTestKernel::new(
            move |remote: NodeRemote<StackedRatchet>, events: Events| async move {
                let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
                let first = conn
                    .find_target(conn.cid, peer)
                    .await?
                    .connect_to_peer_custom(Default::default(), UdpMode::Enabled, None)
                    .await?;
                let accepting = tokio::spawn(accept_all(events, remote.clone()));
                let udp = expect_udp("dialer", first.udp_channel_rx).await;
                wait_for_peers().await;
                accepting.abort();
                drop((udp, first.channel));
                conn.shutdown_kernel().await
            },
        );

        // Accepts the first dial, then at once dials back, as the workspace's auto-connect does.
        let (me, peer) = (acceptor, dialer);
        let acceptor_node = GroupTestKernel::new(
            move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
                let (channel, offer) = accept_next(&mut events, &remote)
                    .await
                    .expect("the first dial's channel");
                let (cid, dialing) = (conn.cid, conn.clone());
                let second = tokio::spawn(async move {
                    dialing
                        .find_target(cid, peer)
                        .await?
                        .connect_to_peer_custom(Default::default(), UdpMode::Enabled, None)
                        .await
                        .map(|_| ())
                });
                let udp = expect_udp("acceptor", offer).await;
                // The live connection won: the second dial is answered, not left to time out.
                let refused = tokio::time::timeout(DEADLINE, second)
                    .await
                    .expect("the second dial was never answered")
                    .expect("dial task");
                let err = refused.expect_err("a second connection was made over a live one");
                assert!(err.to_string().contains("Already connected"), "{err}");
                wait_for_peers().await;
                drop((udp, channel));
                conn.shutdown_kernel().await
            },
        );

        let clients = futures::future::try_join(
            DefaultNodeBuilder::default()
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .build(dialer_node)
                .unwrap(),
            DefaultNodeBuilder::default()
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .build(acceptor_node)
                .unwrap(),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(180), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("both peers kept the first connection's UDP channel");
        assert!(
            LOGGER.stalls.load(Ordering::SeqCst) >= 2,
            "the punches were never stalled"
        );
    }
}
