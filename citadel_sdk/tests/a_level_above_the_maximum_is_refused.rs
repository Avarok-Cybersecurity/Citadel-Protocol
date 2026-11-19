#![cfg(not(target_family = "wasm"))]
//! A node builds no link above its maximum security level, whoever names the level.
//!
//! Every layer of a link is a key exchange and one more seal on every packet, so the level a
//! dialler builds with cannot be the peer's or the server's to choose without limit. Each
//! place that names it is refused before anything is built:
//! - the accept the dialler receives, which the server relays as the accepter wrote it (or
//!   writes itself when two dials cross): `Custom(254)`, which no ratchet can carry;
//! - the server's merge of two crossed dials, above one dialler's maximum;
//! - a dial above the server's own maximum, which the server neither routes nor merges;
//! - a dial above the dialled side's maximum, which that side declines unasked;
//! - the key exchange a dialler starts at the level the accepter named, above the accepter's own
//!   maximum, which the accepter refuses before building its side.
//!
//! After each refusal both sessions stay up and the pair connects at a level both admit
//! (ordering is by events and barriers, never by sleeps).

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
    use citadel_sdk::test_common::{
        localhost_max_security_level, server_test_node, wait_for_peers, TestBarrier,
    };
    use futures::StreamExt;
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    enum Scenario {
        /// `b` accepts `a`'s Standard dial at `Custom(254)`.
        Accept,
        /// `a` (maximum High) dials Standard; `b` crosses it at `Custom(9)`; the server merges.
        Merge,
        /// `b` dials at `Custom(254)`, above the server's maximum.
        Dial,
        /// `b` dials `a` (maximum High) at `Custom(9)`.
        Offer,
        /// `b` (maximum High) accepts `a`'s Standard dial at `Custom(9)`.
        Kex,
    }

    async fn refusal_on(events: &mut Events, ticket: Ticket) -> String {
        let wait = async {
            while let Some(event) = events.recv().await {
                match event {
                    NodeResult::PeerEvent(PeerEvent {
                        event: PeerSignal::SignalError { error, .. },
                        ticket: t,
                        ..
                    }) if t == ticket => return error,
                    NodeResult::PeerChannelCreated(_) => panic!("a channel opened above a maximum"),
                    _ => {}
                }
            }
            panic!("the event stream ended before the refusal");
        };
        tokio::time::timeout(DEADLINE, wait)
            .await
            .expect("the refusal arrives")
    }

    fn unsupported(error: impl std::fmt::Display) {
        let error = error.to_string();
        assert!(error.contains("Unsupported"), "refused as: {error}");
    }

    async fn one_end(
        scenario: Scenario,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let link = target.try_as_peer_connection().await?;
        let is_a = me.starts_with("a_");
        let command = |signal| {
            NodeRequest::PeerCommand(PeerCommand {
                session_cid: conn.cid,
                command: signal,
            })
        };
        wait_for_peers().await;
        let dial = |level| target.connect_to_peer_custom(settings(level), UdpMode::Disabled, None);
        match (scenario, is_a) {
            (Scenario::Accept | Scenario::Merge | Scenario::Kex, true) => {
                unsupported(dial(SecurityLevel::Standard).await.expect_err("refused"))
            }
            (Scenario::Accept | Scenario::Kex, false) => {
                let level = match scenario {
                    Scenario::Kex => SecurityLevel::Custom(9),
                    _ => SecurityLevel::Custom(254),
                };
                let PeerSignal::PostConnect {
                    peer_conn_type,
                    ticket_opt: Some(ticket),
                    ..
                } = next_offer(&mut events).await
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
                if let Scenario::Accept = scenario {
                    unsupported(refusal_on(&mut events, ticket).await);
                }
            }
            (Scenario::Offer, true) => {}
            (Scenario::Offer, false) => {
                let _declined = dial(SecurityLevel::Custom(9))
                    .await
                    .expect_err("the dialled side declines above its maximum");
            }
            (Scenario::Merge, false) => {
                let _unanswered = next_offer(&mut events).await;
                let _refused = dial(SecurityLevel::Custom(9))
                    .await
                    .expect_err("the merge was refused by the other dialler");
            }
            (Scenario::Dial, true) => {}
            (Scenario::Dial, false) => {
                let above = post_connect(link, SecurityLevel::Custom(254));
                let ticket = remote.send(command(above)).await?;
                unsupported(refusal_on(&mut events, ticket).await);
            }
        }
        wait_for_peers().await;
        // Both sessions are still up, and a level both admit connects the pair.
        let channel = if is_a {
            channel_from(Some(dial(SecurityLevel::Standard)), &mut events).await
        } else {
            let offer = offer_put_to_kernel(&mut events).await;
            let PeerSignal::PostConnect {
                session_security_settings,
                ..
            } = &offer
            else {
                unreachable!()
            };
            assert_eq!(
                session_security_settings.security_level.value(),
                0,
                "the first offer to reach the kernel is the honest one"
            );
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            channel_from(None::<std::future::Pending<_>>, &mut events).await
        };
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

    async fn run(scenario: Scenario) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let high = || MaxSecurityLevel::new(SecurityLevel::High).unwrap();
        let (a_max, b_max) = match scenario {
            Scenario::Merge | Scenario::Offer => (high(), localhost_max_security_level()),
            Scenario::Kex => (localhost_max_security_level(), high()),
            _ => (
                localhost_max_security_level(),
                localhost_max_security_level(),
            ),
        };
        let node = |me: String, peer: String, max: MaxSecurityLevel| {
            DefaultNodeBuilder::default()
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(max)
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(scenario, remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients =
            futures::future::try_join(node(a.clone(), b.clone(), a_max), node(b, a, b_max));
        let outcome = tokio::time::timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.unwrap_or_else(|err| panic!("{scenario:?}: {err}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn an_accept_no_ratchet_can_carry_is_refused_by_the_dialler() {
        run(Scenario::Accept).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_merge_above_a_diallers_maximum_is_refused_by_it() {
        run(Scenario::Merge).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dial_above_the_servers_maximum_is_not_routed() {
        run(Scenario::Dial).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dial_above_the_dialled_sides_maximum_is_declined() {
        run(Scenario::Offer).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_key_exchange_above_the_accepters_maximum_is_refused() {
        run(Scenario::Kex).await;
    }
}
