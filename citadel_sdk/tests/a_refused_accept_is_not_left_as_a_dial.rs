#![cfg(not(target_family = "wasm"))]
//! An accept the server refuses ends there: it is not kept as an attempt of the accepter's own.
//!
//! The higher-CID end accepts an offer the server has already superseded (the lower CID dialled
//! again), and the server refuses that accept. The accept had been recorded as an outgoing
//! attempt when it was sent; it must end with the refusal. Otherwise the higher CID's client
//! tiebreak reads the leftover as a dial of its own, defers to the lower CID, and the lower CID's
//! next dial never reaches the higher CID's kernel.
//!
//! The lower-CID side of the same refusal is `order_b_a_refused_bid_is_not_held` in
//! `crossed_dials_take_the_stronger_offer.rs`. Ordering is by events and barriers.

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
    use crate::dials::{next_offer, post_connect, settings, DEADLINE};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::time::Duration;

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
        wait_for_peers().await;
        let level = SecurityLevel::Standard;
        if conn.cid < link.get_original_target_cid() {
            // Lower CID: dial, redial (superseding the first), then dial once more.
            remote.send(command(post_connect(link, level))).await?;
            remote.send(command(post_connect(link, level))).await?;
            wait_for_peers().await;
            remote.send(command(post_connect(link, level))).await?;
            wait_for_peers().await;
        } else {
            // Higher CID: accept the superseded offer; the server refuses it.
            let superseded = next_offer(&mut events).await;
            let _redial = next_offer(&mut events).await;
            let PeerSignal::PostConnect {
                peer_conn_type,
                ticket_opt: Some(ticket),
                ..
            } = superseded
            else {
                panic!("an offer carries its ticket");
            };
            let accept = PeerSignal::PostConnect {
                peer_conn_type: peer_conn_type.reverse(),
                ticket_opt: Some(ticket),
                invitee_response: Some(PeerResponse::Accept(None)),
                session_security_settings: settings(level),
                udp_mode: UdpMode::Disabled,
                session_password: None,
            };
            remote
                .send_with_custom_ticket(ticket, command(accept))
                .await?;
            let refused = async {
                while let Some(event) = events.recv().await {
                    if let NodeResult::PeerEvent(PeerEvent {
                        event: PeerSignal::SignalError { .. },
                        ticket: t,
                        ..
                    }) = event
                    {
                        if t == ticket {
                            return;
                        }
                    }
                }
                panic!("event stream ended before the accept was answered");
            };
            tokio::time::timeout(DEADLINE, refused)
                .await
                .expect("the server refuses the stale accept");
            wait_for_peers().await;
            let fresh =
                tokio::time::timeout(Duration::from_secs(15), next_offer(&mut events)).await;
            wait_for_peers().await;
            if fresh.is_err() {
                return Err(NetworkError::msg(
                    "the lower CID's next dial never reached the higher CID's kernel: the refused accept was kept as an attempt",
                ));
            }
        }
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_refused_accept_is_not_left_as_a_dial() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String| {
            DefaultNodeBuilder::default()
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_link_manager(citadel_sdk::prelude::LinkManagerMode::Legacy)
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
        let outcome = tokio::time::timeout(Duration::from_secs(90), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("the higher CID's kernel sees the fresh dial");
    }
}
