#![cfg(not(target_family = "wasm"))]
//! A dial over a live link is answered, not left to time out.
//!
//! The pair is connected. `b` dials `a` again (a dial of its own is now in progress), then `a`
//! dials `b`. `b`'s client will not start a second exchange over the live link, and it used to
//! drop `a`'s dial without a word, so `a` waited out its whole connect timeout. It must be
//! declined, promptly.
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
    use crate::dials::{channel_from, next_offer, post_connect, settings, DEADLINE};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::time::Duration;

    const LEVEL: SecurityLevel = SecurityLevel::Standard;

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
            let _live = channel_from(Some(dial()), &mut events).await;
            wait_for_peers().await;
            // b's dial over the live link is put to this kernel; it is left unanswered.
            let _b_dials = next_offer(&mut events).await;
            let answered = tokio::time::timeout(DEADLINE, dial())
                .await
                .map_err(|_| NetworkError::msg("a dial over the live link was never answered"))?;
            assert!(answered.is_err(), "a second link was made over a live one");
            wait_for_peers().await;
        } else {
            let offer = next_offer(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            let _live = channel_from(None::<std::future::Pending<_>>, &mut events).await;
            wait_for_peers().await;
            let again = NodeRequest::PeerCommand(PeerCommand {
                session_cid: conn.cid,
                command: post_connect(link, LEVEL),
            });
            remote.send(again).await?;
            wait_for_peers().await;
        }
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dial_over_a_live_link_is_declined_promptly() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String| {
            DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
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
        outcome.expect("the dial over the live link is answered");
    }
}
