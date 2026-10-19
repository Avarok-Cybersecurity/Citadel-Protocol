//! Losing a P2P connection's direct route is not the end of the connection, and must not be
//! reported to the application as one.
//!
//! When the direct stream's reader fails, the connection falls back to the server relay and
//! carries on (`fall_back_to_server_relay`). The session's stream-error handler nonetheless sent
//! the kernel a `PeerEvent::Disconnect` naming the live connection, before the fall-back ran.
//! An application cannot tell that from a real end: the workspace agent removed the peer,
//! dropped its channel and call, and redialled, so a call whose direct path was lost never got
//! its UDP back on the connection that had survived.
//!
//! Here the direct path is killed under a live connection; once the channel is on the relay and
//! a message has crossed it both ways, neither peer may have been told the connection ended.
//! (The bad report was queued before the path cell switched to the relay, so it is in the event
//! queue by the time the round trip is done.)
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;
mod relay_pair;

#[cfg(all(test, feature = "localhost-testing", unix))]
mod tests {
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use crate::relay_pair::pair::kill_udp_socket;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use futures::StreamExt;
    use std::time::Duration;

    type UdpOffer = Option<tokio::sync::oneshot::Receiver<UdpChannel<StackedRatchet>>>;

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

    /// Loses the direct path under a live connection, then requires the relay to carry a message
    /// each way and no Disconnect to have been reported.
    async fn lose_the_direct_route(
        killer: bool,
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
        if killer {
            // Both ends of the direct path live in this process.
            assert!(kill_udp_socket(udp_tx.local_addr()) > 0);
            assert!(kill_udp_socket(udp_tx.remote_addr()) > 0);
        }
        changes
            .wait_for(|s| s.path == P2pPath::ServerRelay)
            .await
            .expect("the connection closed instead of falling back");
        tx.send(SecBuffer::from(&b"over the relay"[..]))
            .await
            .expect("send over the relay");
        let got = tokio::time::timeout(Duration::from_secs(30), rx.next())
            .await
            .expect("nothing crossed the relay")
            .expect("the channel ended");
        assert_eq!(got.as_ref(), b"over the relay");
        while let Ok(event) = events.try_recv() {
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
        wait_for_peers().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_direct_route_is_not_reported_as_a_disconnect() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (dialer, acceptor) = (format!("dial_{tag}"), format!("acc_{tag}"));

        let (me, peer) = (dialer.clone(), acceptor.clone());
        let dialer_node = GroupTestKernel::new(move |remote, mut events: Events| async move {
            let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
            let mut ok = conn
                .find_target(conn.cid, peer)
                .await?
                .connect_to_peer_custom(Default::default(), UdpMode::Enabled, None)
                .await?;
            let offer = ok.udp_channel_rx.take();
            lose_the_direct_route(true, ok.channel, offer, &mut events).await;
            conn.shutdown_kernel().await
        });
        let (me, peer) = (acceptor, dialer);
        let acceptor_node = GroupTestKernel::new(move |remote, mut events: Events| async move {
            let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
            let (channel, offer) = accept_next(&mut events, &remote).await;
            lose_the_direct_route(false, channel, offer, &mut events).await;
            conn.shutdown_kernel().await
        });

        let clients = futures::future::try_join(
            DefaultNodeBuilder::default().build(dialer_node).unwrap(),
            DefaultNodeBuilder::default().build(acceptor_node).unwrap(),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("both peers kept the connection");
    }
}
