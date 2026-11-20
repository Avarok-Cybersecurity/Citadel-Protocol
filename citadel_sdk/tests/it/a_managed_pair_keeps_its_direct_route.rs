//! A P2P pair under `LinkManagerMode::Managed` (§12.4): the RobustConnectionManager, not the
//! campaign, keeps the pair's route. Its first punch attaches a direct route; when that route is
//! killed under the live connection, the channel carries on over the relay and the manager
//! punches a new direct route, on the same channel, with no disconnect reported.
//!
//! A Managed node paired with a Legacy one runs the campaign on both ends (WIRE-A): the pair
//! still goes direct.
//!
//! Which code ran is read from the kernel's events: the campaign reports every attempt as a
//! `PeerPathOutcome`; the manager reports through its own events (lane L3 maps them), so a
//! Managed pair's kernel sees none.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing", unix))]
mod tests {
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use crate::relay_pair::pair::kill_udp_socket;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{
        localhost_link_policy, server_test_node, wait_for_peers, TestBarrier,
    };
    use futures::StreamExt;
    use std::time::Duration;

    type UdpOffer = Option<tokio::sync::oneshot::Receiver<UdpChannel<StackedRatchet>>>;

    /// A pair end runs `Managed` (`true`) or `Legacy` (`false`).
    const MANAGED: bool = true;
    const LEGACY: bool = false;

    fn node(managed: bool) -> DefaultNodeBuilder {
        let mode = if managed {
            let clock = std::sync::Arc::new(RuntimeClock::new());
            LinkManagerMode::Managed(ManagedLinks::new(clock, localhost_link_policy()).unwrap())
        } else {
            LinkManagerMode::Legacy
        };
        let mut builder = citadel_sdk::test_common::node_builder();
        builder
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .with_link_manager(mode);
        builder
    }

    async fn accept_next(
        events: &mut Events,
        remote: &NodeRemote<StackedRatchet>,
    ) -> (PeerChannel<StackedRatchet>, UdpOffer) {
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
                    return (*created.channel, created.udp_rx_opt);
                }
                _ => {}
            }
        }
        panic!("event stream ended before the channel")
    }

    /// Goes direct; with `heal`, loses the route and requires a new direct route on the same
    /// channel, a message each way, and no Disconnect.
    async fn exercise(
        killer: bool,
        heal: bool,
        campaign: bool,
        mut channel: PeerChannel<StackedRatchet>,
        offer: UdpOffer,
        events: &mut Events,
    ) {
        let cell = channel.p2p_path_cell();
        assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
        let udp = offer.expect("UDP enabled").await.expect("a UDP channel");
        let (udp_tx, _udp_rx) = udp.split();
        let mut changes = channel.path_changes();
        let _restored = channel.take_restored_udp();
        let (mut tx, mut rx) = channel.split();
        wait_for_peers().await;
        if heal {
            if killer {
                assert!(kill_udp_socket(udp_tx.local_addr()) > 0);
                assert!(kill_udp_socket(udp_tx.remote_addr()) > 0);
            }
            changes
                .wait_for(|s| s.path == P2pPath::ServerRelay)
                .await
                .expect("the connection closed instead of falling back");
            tokio::time::timeout(
                Duration::from_secs(90),
                changes.wait_for(|s| s.path == P2pPath::Direct),
            )
            .await
            .expect("the manager never punched a new direct route")
            .expect("the connection closed instead of healing");
        }
        tx.send(SecBuffer::from(&b"after"[..])).await.expect("send");
        let got = tokio::time::timeout(Duration::from_secs(30), rx.next())
            .await
            .expect("nothing crossed")
            .expect("the channel ended");
        assert_eq!(got.as_ref(), b"after");
        let mut outcomes = 0;
        while let Ok(event) = events.try_recv() {
            outcomes += usize::from(matches!(event, NodeResult::PeerPathOutcome(_)));
            assert!(
                !matches!(
                    event,
                    NodeResult::PeerEvent(PeerEvent {
                        event: PeerSignal::Disconnect { .. },
                        ..
                    })
                ),
                "a live connection was reported as ended: {event:?}"
            );
        }
        assert_eq!(
            outcomes > 0,
            campaign,
            "the pair ran the wrong link code ({outcomes} campaign outcomes)"
        );
        wait_for_peers().await;
    }

    async fn pair(dialer_managed: bool, acceptor_managed: bool, heal: bool) {
        let campaign = !(dialer_managed && acceptor_managed);
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (dialer, acceptor) = (format!("mdial_{tag}"), format!("macc_{tag}"));

        let (me, peer) = (dialer.clone(), acceptor.clone());
        let dialer_node = GroupTestKernel::new(move |remote, mut events: Events| async move {
            let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
            let mut ok = conn
                .find_target(conn.cid, peer)
                .await?
                .connect_to_peer_custom(
                    citadel_sdk::prelude::default_session_security_settings(),
                    UdpMode::Enabled,
                    None,
                )
                .await?;
            let offer = ok.udp_channel_rx.take();
            exercise(true, heal, campaign, ok.channel, offer, &mut events).await;
            conn.shutdown_kernel().await
        });
        let (me, peer) = (acceptor, dialer);
        let acceptor_node = GroupTestKernel::new(move |remote, mut events: Events| async move {
            let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
            let (channel, offer) = accept_next(&mut events, &remote).await;
            exercise(false, heal, campaign, channel, offer, &mut events).await;
            conn.shutdown_kernel().await
        });

        let clients = futures::future::try_join(
            node(dialer_managed).build(dialer_node).unwrap(),
            node(acceptor_managed).build(acceptor_node).unwrap(),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(200), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("both peers kept the connection");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_managed_pair_punches_a_new_direct_route_after_losing_one() {
        pair(MANAGED, MANAGED, true).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_managed_node_and_a_legacy_node_go_direct_under_the_campaign() {
        pair(MANAGED, LEGACY, false).await;
    }
}
