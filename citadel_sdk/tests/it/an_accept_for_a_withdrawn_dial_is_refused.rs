#![cfg(not(target_family = "wasm"))]
//! An accept for a dial this end no longer holds is refused back, and starts nothing.
//!
//! `p` dials `r` (`r` leaves it unanswered), then declines `r` -- which withdraws `p`'s own dial.
//! `p`'s posting is still on the server, so when `r` dials, the server merges the two and answers
//! `p` with an accept on `r`'s behalf. `p` holds no dial to accept: it must refuse, so `r`'s dial
//! is answered at once instead of waiting out its timeout, and `p` must record no key exchange --
//! `r`'s next dial is put to `p`'s kernel and connects. `p` is the lower CID, the end on which a
//! leftover exchange would drop the next one's first key-exchange stage.
//!
//! Ordering is by events and barriers, never by sleeps.

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
        let command = |signal| {
            NodeRequest::PeerCommand(PeerCommand {
                session_cid: conn.cid,
                command: signal,
            })
        };
        let dial = || target.connect_to_peer_custom(settings(LEVEL), UdpMode::Disabled, None);
        let lower = conn.cid < link.get_original_target_cid();
        wait_for_peers().await;
        if lower {
            // p: dial, and once the dial is put to r, withdraw it by declining r.
            remote.send(command(post_connect(link, LEVEL))).await?;
            wait_for_peers().await;
            let decline = PeerSignal::PostConnect {
                peer_conn_type: link,
                ticket_opt: None,
                invitee_response: Some(PeerResponse::Decline),
                session_security_settings: settings(LEVEL),
                udp_mode: UdpMode::Disabled,
                session_password: None,
            };
            remote.send(command(decline)).await?;
            wait_for_peers().await;
            // r dials twice; the first meets the stale posting.
            wait_for_peers().await;
            let redial = offer_put_to_kernel(&mut events).await;
            citadel_sdk::responses::peer_connect(redial, true, &remote, None).await?;
            let _channel = channel_from(None::<std::future::Pending<_>>, &mut events).await;
        } else {
            // r: the withdrawn dial is put to this kernel and left unanswered.
            let _unanswered = next_offer(&mut events).await;
            wait_for_peers().await;
            wait_for_peers().await;
            let refused = tokio::time::timeout(DEADLINE, dial()).await.map_err(|_| {
                NetworkError::msg("the dial met by p's stale posting was never answered")
            })?;
            assert!(
                refused.is_err(),
                "p connected for a dial it had withdrawn: an accept nobody gave"
            );
            wait_for_peers().await;
            let _channel = channel_from(Some(dial()), &mut events).await;
        }
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn an_accept_for_a_withdrawn_dial_is_refused_and_starts_nothing() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String| {
            citadel_sdk::test_common::node_builder()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
        let outcome = citadel_io::time::runnable_timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("the forged accept is refused and the next dial connects");
    }
}
