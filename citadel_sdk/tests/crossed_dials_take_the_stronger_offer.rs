#![cfg(not(target_family = "wasm"))]
//! When two peers dial each other, the link takes the stronger of the two offers.
//!
//! Nobody accepts a crossed dial: the protocol answers both with one link. It used to take the
//! settings of whichever offer it processed second, so a chat one side had raised to Extreme
//! came up at the other side's Standard. Each end here reads the level its channel was actually
//! established with.
//!
//! Two places decide a crossing, and each scenario reaches one of them:
//! - the server merge, when the second dial reaches the server while the first is pending
//!   (both orders: the stronger offer first, and second);
//! - the client tiebreak, when an offer reaches the lower CID while it holds a dial of its own.
//!   On one server that dial always reaches the server first (it precedes the tiebreak's accept
//!   on the lower CID's ordered stream), the server merges the crossing, and the tiebreak's
//!   accept is refused: the link is the server merge's. The tiebreak's own result can decide a
//!   link only through a bid the server no longer holds, and a bid the server refused is no
//!   longer held (`order_b`), so on one server that is unreachable.
//!
//! Ordering is by events and barriers, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/dials.rs"]
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

    #[derive(Clone, Copy)]
    enum Scenario {
        /// `a` dials at `first`; `b`, once it sees that offer, dials at `second`.
        ServerMerge {
            first: SecurityLevel,
            second: SecurityLevel,
        },
        /// The lower CID's accept at `bid`, refused; the higher CID's next dial at `redial`.
        RefusedBid {
            bid: SecurityLevel,
            redial: SecurityLevel,
        },
    }

    async fn one_end(
        scenario: Scenario,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
        expected: SecurityLevel,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let link = target.try_as_peer_connection().await?;
        wait_for_peers().await;
        let dial = |level| target.connect_to_peer_custom(settings(level), UdpMode::Disabled, None);
        let channel = match scenario {
            Scenario::ServerMerge { first, second } => {
                if me.starts_with("a_") {
                    channel_from(Some(dial(first)), &mut events).await
                } else {
                    let _unanswered = next_offer(&mut events).await;
                    channel_from(Some(dial(second)), &mut events).await
                }
            }
            Scenario::RefusedBid { bid, redial } => {
                let command = |signal| {
                    NodeRequest::PeerCommand(PeerCommand {
                        session_cid: conn.cid,
                        command: signal,
                    })
                };
                if conn.cid < link.get_original_target_cid() {
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
                    let bid = PeerSignal::PostConnect {
                        peer_conn_type: peer_conn_type.reverse(),
                        ticket_opt: Some(ticket),
                        invitee_response: Some(PeerResponse::Accept(None)),
                        session_security_settings: settings(bid),
                        udp_mode: UdpMode::Disabled,
                        session_password: None,
                    };
                    remote.send_with_custom_ticket(ticket, command(bid)).await?;
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
                        panic!("the event stream ended before the bid was answered");
                    };
                    tokio::time::timeout(DEADLINE, refused)
                        .await
                        .expect("the server refuses the stale accept");
                    wait_for_peers().await;
                    // The refused bid is not a dial: the next one is put to this kernel.
                    let offer = offer_put_to_kernel(&mut events).await;
                    citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
                    channel_from(None::<std::future::Pending<_>>, &mut events).await
                } else {
                    remote.send(command(post_connect(link, redial))).await?;
                    remote.send(command(post_connect(link, redial))).await?;
                    wait_for_peers().await;
                    channel_from(Some(dial(redial)), &mut events).await
                }
            }
        };
        assert_eq!(
            channel.session_security_settings().security_level.value(),
            expected.value(),
            "{me}'s link to {peer} was established at {:?}, not the stronger offer {expected:?}",
            channel.session_security_settings().security_level
        );
        let (mut tx, mut rx) = channel.split();
        tx.send(SecBuffer::from(me.as_bytes())).await?;
        let heard = tokio::time::timeout(DEADLINE, rx.next())
            .await
            .expect("the peer's message")
            .expect("open channel");
        assert_eq!(heard.as_ref(), peer.as_bytes());
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    async fn run(scenario: Scenario, expected: SecurityLevel) {
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
                    one_end(scenario, remote, events, addr, me, peer, expected)
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
        let outcome = tokio::time::timeout(Duration::from_secs(180), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("both ends hold a channel at the stronger level");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn order_a_the_stronger_offer_dialled_first() {
        let (first, second) = (SecurityLevel::Extreme, SecurityLevel::Standard);
        run(
            Scenario::ServerMerge { first, second },
            SecurityLevel::Extreme,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn order_a_the_stronger_offer_dialled_second() {
        let (first, second) = (SecurityLevel::Standard, SecurityLevel::Extreme);
        run(
            Scenario::ServerMerge { first, second },
            SecurityLevel::Extreme,
        )
        .await;
    }

    /// The lower CID's refused accept leaves nothing behind: the higher CID's next dial is put
    /// to the lower CID's kernel, which accepts it, and the link takes that dial's offer -- not
    /// the stronger bid the server refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn order_b_a_refused_bid_is_not_held() {
        let (bid, redial) = (SecurityLevel::Extreme, SecurityLevel::Standard);
        run(
            Scenario::RefusedBid { bid, redial },
            SecurityLevel::Standard,
        )
        .await;
    }
}
