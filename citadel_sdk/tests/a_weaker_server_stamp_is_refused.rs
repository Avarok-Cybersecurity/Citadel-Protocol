#![cfg(not(target_family = "wasm"))]
//! A client never builds a link below its own offer (R-DIAL 3: servers stamp, clients verify).
//!
//! The settings a dialler builds its link with are the ones in the accept the server delivers
//! to it: the server's merge when two dials crossed, otherwise the accepter's answer, which the
//! server relays as it stands. Either way the dialler sees one stamp and makes one check. Here
//! the stamp is Standard against an Extreme offer: the accepter answers with Standard. The
//! dialler refuses: its dial fails with `BelowPolicy`, no key exchange starts, and the accepter
//! hears the refusal on its accept's ticket.
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
    use crate::dials::{next_offer, settings, DEADLINE};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::time::Duration;

    async fn refusal_of(events: &mut Events, ticket: Ticket) -> String {
        let wait = async {
            while let Some(event) = events.recv().await {
                match event {
                    NodeResult::PeerEvent(PeerEvent {
                        event: PeerSignal::SignalError { error, .. },
                        ticket: t,
                        ..
                    }) if t == ticket => return error,
                    NodeResult::PeerChannelCreated(_) => {
                        panic!("a channel opened below the dialler's offer")
                    }
                    _ => {}
                }
            }
            panic!("the event stream ended before the refusal");
        };
        tokio::time::timeout(DEADLINE, wait)
            .await
            .expect("the accepter hears the refusal")
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
        wait_for_peers().await;
        if me.starts_with("a_") {
            let dial = target
                .connect_to_peer_custom(settings(SecurityLevel::Extreme), UdpMode::Disabled, None)
                .await;
            let err = dial.expect_err("a link stamped below the offer must not open");
            assert!(
                err.to_string().contains("BelowPolicy"),
                "the dial fails as BelowPolicy, not: {err}"
            );
        } else {
            let PeerSignal::PostConnect {
                peer_conn_type,
                ticket_opt: Some(ticket),
                ..
            } = next_offer(&mut events).await
            else {
                panic!("an offer carries its ticket");
            };
            let weaker = PeerSignal::PostConnect {
                peer_conn_type: peer_conn_type.reverse(),
                ticket_opt: Some(ticket),
                invitee_response: Some(PeerResponse::Accept(None)),
                session_security_settings: settings(SecurityLevel::Standard),
                udp_mode: UdpMode::Disabled,
                session_password: None,
            };
            let command = NodeRequest::PeerCommand(PeerCommand {
                session_cid: conn.cid,
                command: weaker,
            });
            remote.send_with_custom_ticket(ticket, command).await?;
            let error = refusal_of(&mut events, ticket).await;
            assert!(error.starts_with("BelowPolicy"), "refused as: {error}");
        }
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_weaker_server_stamp_is_refused() {
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
        outcome.expect("the dialler refuses the weaker stamp");
    }
}
