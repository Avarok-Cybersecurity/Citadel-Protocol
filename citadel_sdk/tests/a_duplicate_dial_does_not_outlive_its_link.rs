#![cfg(not(target_family = "wasm"))]
//! A dial made while the pair's link is being established is not matched against a later one.
//!
//! `a` dials and `b` accepts, then `b` at once dials `a` as well, as an agent that both answers
//! offers and dials its contacts does. That duplicate reaches the server after it forged the pair,
//! and reaches `a` mid key exchange, where it is folded into the exchange in progress and not
//! answered. Its server posting used to stay matchable for its whole TTL: after a disconnect,
//! `a`'s redial was matched against it, the server answered `a` with an accept on `b`'s behalf, and
//! `b` -- no longer dialling, its session password for `a` dropped -- started a key exchange that
//! never completed. Here the redial must be put to `b`'s kernel and connect.
//!
//! Ordering is by events and barriers, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/dials.rs"]
#[allow(dead_code)]
mod dials;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{
        channel_from, next_offer, offer_put_to_kernel, post_connect, settings, DEADLINE,
    };
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use futures::StreamExt;
    use std::time::Duration;

    const LEVEL: SecurityLevel = SecurityLevel::Standard;

    type Halves = (
        PeerChannelSendHalf<StackedRatchet>,
        PeerChannelRecvHalf<StackedRatchet>,
    );

    /// Each end says its name and hears the other's. The halves are returned so the channel stays
    /// open: dropping it ends the connection, and only the explicit disconnect may do that here.
    async fn exchange(
        channel: PeerChannel<StackedRatchet>,
        me: &str,
        peer: &str,
    ) -> Result<Halves, NetworkError> {
        let (mut tx, mut rx) = channel.split();
        tx.send(SecBuffer::from(me.as_bytes())).await?;
        let heard = tokio::time::timeout(DEADLINE, rx.next())
            .await
            .map_err(|_| NetworkError::msg(format!("{me} never heard {peer}")))?
            .ok_or_else(|| NetworkError::msg(format!("{me}'s channel to {peer} closed")))?;
        assert_eq!(heard.as_ref(), peer.as_bytes());
        Ok((tx, rx))
    }

    async fn the_peers_disconnect(events: &mut Events) {
        let wait = async {
            while let Some(event) = events.recv().await {
                if let NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::Disconnect { .. },
                    ..
                }) = event
                {
                    return;
                }
            }
            panic!("the event stream ended before the peer disconnected");
        };
        tokio::time::timeout(DEADLINE, wait)
            .await
            .expect("the peer's disconnect is relayed");
    }

    async fn one_end(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let link = target.try_as_peer_connection().await?;
        let dial = || target.connect_to_peer_custom(settings(LEVEL), UdpMode::Disabled, None);
        wait_for_peers().await;
        if me.starts_with("a_") {
            let first = channel_from(Some(dial()), &mut events).await;
            let first = exchange(first, &me, &peer).await?;
            wait_for_peers().await;
            target.disconnect().await?;
            drop(first);
            wait_for_peers().await;
            let redial = tokio::time::timeout(DEADLINE, dial())
                .await
                .map_err(|_| NetworkError::msg("the redial was never answered"))??;
            let _second = exchange(redial.channel, &me, &peer).await?;
            wait_for_peers().await;
        } else {
            let offer = next_offer(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            let duplicate = NodeRequest::PeerCommand(PeerCommand {
                session_cid: conn.cid,
                command: post_connect(link, LEVEL),
            });
            remote.send(duplicate).await?;
            let first = channel_from(None::<std::future::Pending<_>>, &mut events).await;
            let first = exchange(first, &me, &peer).await?;
            wait_for_peers().await;
            the_peers_disconnect(&mut events).await;
            drop(first);
            wait_for_peers().await;
            let redial = offer_put_to_kernel(&mut events).await;
            citadel_sdk::responses::peer_connect(redial, true, &remote, None).await?;
            let second = channel_from(None::<std::future::Pending<_>>, &mut events).await;
            let _second = exchange(second, &me, &peer).await?;
            wait_for_peers().await;
        }
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_redial_is_not_matched_against_a_duplicate_dial_from_the_last_link() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String| {
            DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
        let outcome = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("the redial connects, put to the peer's kernel");
    }
}
