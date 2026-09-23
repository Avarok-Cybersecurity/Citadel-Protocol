//! Two SDK peers behind a test server establish P2P through a TURN relay (coturn) when the
//! direct path is ruled out (`TurnPolicy::RelayOnly`), then exchange reliable messages and a
//! media-sized datagram over the relayed UDP channel. Controls: without a TURN config the same pair
//! connects directly; with a TURN config whose server is unreachable it stays server-relayed.
//!
//! The coturn cases need `turnserver` on PATH and are ignored by default:
//! `cargo nextest run -p citadel_sdk --features localhost-testing --test turn_relay_p2p
//! --run-ignored all`.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "../../citadel_wire/tests/common/coturn.rs"]
mod coturn;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::coturn::{Coturn, PASSWORD, USER};
    use citadel_io::tokio;
    use citadel_sdk::media::RECOMMENDED_UDP_PAYLOAD_BUDGET;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use std::net::SocketAddr;
    use std::ops::RangeInclusive;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    /// What the pair must observe.
    #[derive(Clone)]
    struct Expect {
        path: P2pPath,
        /// When set, the UDP channel must exist and the sides' datagrams must be addressed to a
        /// relayed address in this port range (proof the traffic crosses the relay): one side
        /// with a single allocation, both sides relay-to-relay.
        relay_ports: Option<RangeInclusive<u16>>,
        udp: bool,
        /// Both peers relay through their own allocation (`PeerChannel::p2p_relayed_both`).
        relayed_both: bool,
    }

    fn relay_config(url: &str, policy: TurnPolicy) -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![TurnServerCredential::new(url, USER, PASSWORD, None).unwrap()],
            policy,
        )
    }

    /// Returns the halves: dropping the receive half tears the P2P connection down, so they must
    /// outlive the UDP exchange.
    async fn exchange_reliable<R: Ratchet>(
        channel: PeerChannel<R>,
        me: usize,
    ) -> (PeerChannelSendHalf<R>, PeerChannelRecvHalf<R>) {
        let (mut tx, mut rx) = channel.split();
        tx.send(format!("hello from {me}").into_bytes())
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(20), rx.next())
            .await
            .expect("reliable message did not arrive")
            .expect("reliable channel closed");
        assert_eq!(msg.as_ref(), format!("hello from {}", 1 - me).as_bytes());
        wait_for_peers().await;
        (tx, rx)
    }

    /// Resends until the peer's datagram arrives (UDP may drop), then keeps sending briefly so the
    /// peer is never stranded waiting for ours.
    async fn exchange_media_datagram<R: Ratchet>(udp: UdpChannel<R>, path: P2pPath) -> SocketAddr {
        let (tx, mut rx) = udp.split();
        if path == P2pPath::Turn {
            // One ChannelData header per client leg, however many allocations: the relayed MTU,
            // minus quinn's 38-byte datagram overhead, is the ceiling on every relayed path.
            assert_eq!(
                tx.max_datagram_len(),
                citadel_wire::quic::RELAYED_QUIC_MTU as usize - 38,
                "relayed datagram ceiling"
            );
        }
        let max = tx.max_payload_len();
        assert!(
            max >= RECOMMENDED_UDP_PAYLOAD_BUDGET,
            "relayed UDP budget {max} cannot carry media's {RECOMMENDED_UDP_PAYLOAD_BUDGET}"
        );
        let payload = vec![0xC7u8; RECOMMENDED_UDP_PAYLOAD_BUDGET];
        let mut delivered = false;
        for _ in 0..100 {
            tx.unbounded_send(&payload[..]).unwrap();
            if let Ok(Some(got)) = tokio::time::timeout(Duration::from_millis(200), rx.next()).await
            {
                assert_eq!(got.as_ref(), &payload[..]);
                delivered = true;
                break;
            }
        }
        assert!(delivered, "no media-sized datagram crossed the UDP channel");
        for _ in 0..10 {
            let _ = tx.unbounded_send(&payload[..]);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let remote = tx.remote_addr();
        citadel_sdk::test_common::finish_udp_channel(tx, rx).await;
        remote
    }

    /// `trust`: a certificate the nodes' TLS client config must accept (coturn's self-signed
    /// `turns:` certificate); `None` keeps the native root store.
    async fn run_pair(turn: Option<TurnRelayConfig>, trust: Option<Vec<u8>>, expect: Expect) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let succeeded = &AtomicUsize::new(0);
        let relayed_remotes = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();

        for me in 0..2 {
            let expect = expect.clone();
            let mut peer = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Enabled);
            if let Some(turn) = turn.clone() {
                peer = peer.with_turn_config(turn);
            }
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let kernel = PeerConnectionKernel::new(
                settings,
                peer.add(),
                move |mut results, remote| async move {
                    let mut conn = results.recv().await.unwrap().unwrap();
                    assert_eq!(conn.channel.p2p_path(), expect.path, "peer {me} path");
                    assert_eq!(
                        conn.channel.p2p_relayed_both(),
                        expect.relayed_both,
                        "peer {me} relay-to-relay"
                    );
                    let udp_rx = conn.udp_channel_rx.take().expect("UDP mode is enabled");
                    let reliable = exchange_reliable(conn.channel, me).await;
                    let udp = tokio::time::timeout(Duration::from_secs(10), udp_rx).await;
                    if expect.udp {
                        let udp = udp.expect("UDP channel never arrived").unwrap();
                        let remote_addr = exchange_media_datagram(udp, expect.path).await;
                        if let Some(ports) = &expect.relay_ports {
                            if ports.contains(&remote_addr.port()) {
                                relayed_remotes.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    } else {
                        assert!(
                            !matches!(udp, Ok(Ok(_))),
                            "a UDP channel exists without any P2P path"
                        );
                        wait_for_peers().await;
                    }
                    wait_for_peers().await;
                    drop(reliable);
                    succeeded.fetch_add(1, Ordering::SeqCst);
                    remote.shutdown_kernel().await
                },
            );
            let mut builder = DefaultNodeBuilder::default();
            if let Some(cert) = &trust {
                builder.with_custom_certs(&[cert]).unwrap();
            }
            let client = builder.build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(succeeded.load(Ordering::SeqCst), 2);
        if expect.relay_ports.is_some() {
            // The dialer addresses the relayed address; the allocator addresses the dialer.
            assert_eq!(
                relayed_remotes.load(Ordering::SeqCst),
                if expect.relayed_both { 2 } else { 1 },
                "no side sent via the relay"
            );
        }
    }

    #[ignore = "needs coturn (turnserver) on PATH"]
    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_runs_over_a_turn_relay_when_direct_is_ruled_out() {
        let coturn = Coturn::start(Duration::from_secs(600));
        run_pair(
            Some(relay_config(&coturn.url("udp"), TurnPolicy::RelayOnly)),
            None,
            Expect {
                path: P2pPath::Turn,
                relay_ports: Some(coturn.relay_ports.clone()),
                udp: true,
                relayed_both: false,
            },
        )
        .await;
    }

    /// Relay-to-relay: the only TURN URL is TLS, so the dialer has no UDP path to the relay and
    /// allocates its own; both sides send ChannelData through their allocation.
    #[ignore = "needs coturn (turnserver) on PATH"]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dialer_without_udp_relays_through_its_own_allocation() {
        let coturn = Coturn::start(Duration::from_secs(600));
        run_pair(
            Some(relay_config(&coturn.url("tls"), TurnPolicy::RelayOnly)),
            Some(coturn.cert_der.clone()),
            Expect {
                path: P2pPath::Turn,
                relay_ports: Some(coturn.relay_ports.clone()),
                udp: true,
                relayed_both: true,
            },
        )
        .await;
    }

    /// Relay-to-relay detected from a failing UDP TURN server: the dialer's STUN to its UDP
    /// server (a closed port) goes unanswered, so it allocates over TCP instead.
    #[ignore = "needs coturn (turnserver) on PATH"]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dialer_whose_udp_turn_fails_relays_through_its_own_allocation() {
        let coturn = Coturn::start(Duration::from_secs(600));
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed_url = format!("turn:{}?transport=udp", closed.local_addr().unwrap());
        drop(closed);
        let servers = [coturn.url("tcp"), closed_url]
            .iter()
            .map(|url| TurnServerCredential::new(url, USER, PASSWORD, None).unwrap())
            .collect();
        run_pair(
            Some(TurnRelayConfig::new(servers, TurnPolicy::RelayOnly)),
            None,
            Expect {
                path: P2pPath::Turn,
                relay_ports: Some(coturn.relay_ports.clone()),
                udp: true,
                relayed_both: true,
            },
        )
        .await;
    }

    /// Manual live smoke: the same pair relayed through Cloudflare Realtime TURN with TLS 443 as
    /// the only transport, so the dialer cannot use UDP and relays through its own allocation.
    /// Needs a freshly minted short-TTL credential in `CF_TURN_USERNAME` / `CF_TURN_CREDENTIAL`.
    #[ignore = "live: needs CF_TURN_USERNAME / CF_TURN_CREDENTIAL minted from a Cloudflare TURN key"]
    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_runs_over_cloudflare_turn() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));
        let server = TurnServerCredential::new(
            "turns:turn.cloudflare.com:443?transport=tcp",
            var("CF_TURN_USERNAME"),
            var("CF_TURN_CREDENTIAL"),
            Some(std::time::SystemTime::now() + Duration::from_secs(300)),
        )
        .unwrap();
        run_pair(
            Some(TurnRelayConfig::new(vec![server], TurnPolicy::RelayOnly)),
            None,
            Expect {
                path: P2pPath::Turn,
                relay_ports: None,
                udp: true,
                relayed_both: true,
            },
        )
        .await;
    }

    /// Control: the same pair with the TURN config removed attempts (and on loopback gets) the
    /// direct path; nothing is relayed.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_turn_config_the_pair_connects_directly() {
        run_pair(
            None,
            None,
            Expect {
                path: P2pPath::Direct,
                relay_ports: None,
                udp: true,
                relayed_both: false,
            },
        )
        .await;
    }

    /// Control: relay-only with an unreachable TURN server leaves the pair server-relayed — the
    /// reliable channel works, no UDP channel is fulfilled.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_relay_leaves_the_pair_server_relayed() {
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let url = format!("turn:{}?transport=udp", dead.local_addr().unwrap());
        drop(dead);
        run_pair(
            Some(relay_config(&url, TurnPolicy::RelayOnly)),
            None,
            Expect {
                path: P2pPath::ServerRelay,
                relay_ports: None,
                udp: false,
                relayed_both: false,
            },
        )
        .await;
    }
}
