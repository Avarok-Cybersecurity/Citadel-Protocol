#![cfg(not(target_family = "wasm"))]
//! The server relays WebRTC signalling and a peer's errors only between two peers whose connect
//! request was accepted, as it relays their key exchange: an account cannot drive another
//! session's connection setup or report errors into a session it has no connection with.
//!
//! `a` and `b` are connected; `c` is an account on the same server that never connected to `a`.
//! `c`'s signalling and error toward `a` are refused back to `c` and never reach `a`; `b`'s
//! reach `a` and are not refused. Ordering is by events and barriers, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{channel_from, next_offer, settings, DEADLINE};
    use crate::group::{connect, register_connect_and_befriend, Events, GroupTestKernel, PASSWORD};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    type Cids = Arc<[OnceLock<u64>; 2]>;

    fn signals(from: u64, to: u64, tag: &str) -> [PeerSignal; 2] {
        let pair = PeerConnectionType::LocalGroupPeer {
            session_cid: from,
            peer_cid: to,
        };
        [
            PeerSignal::WebRtcSignaling {
                peer_conn_type: pair,
                payload: WebRtcSignalingPayload::Offer {
                    sdp: format!("v=0 {tag}"),
                    ice_candidates: vec![],
                },
            },
            PeerSignal::SignalError {
                ticket: Ticket(0),
                error: format!("from {tag}"),
                peer_connection_type: pair,
            },
        ]
    }

    /// The next error this end hears: its ticket and text.
    async fn next_error(events: &mut Events) -> (Ticket, String) {
        let wait = async {
            while let Some(event) = events.recv().await {
                if let NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::SignalError { error, .. },
                    ticket,
                    ..
                }) = event
                {
                    return (ticket, error);
                }
            }
            panic!("the event stream ended before an error arrived");
        };
        tokio::time::timeout(DEADLINE, wait)
            .await
            .expect("an error arrives")
    }

    /// Sends `signal` on a fresh ticket; an error names that ticket, as a peer's refusal does.
    async fn send(
        remote: &NodeRemote<StackedRatchet>,
        cid: u64,
        mut signal: PeerSignal,
    ) -> Result<Ticket, NetworkError> {
        let ticket = Ticket(rand::random());
        if let PeerSignal::SignalError { ticket: named, .. } = &mut signal {
            *named = ticket;
        }
        let command = NodeRequest::PeerCommand(PeerCommand {
            session_cid: cid,
            command: signal,
        });
        remote.send_with_custom_ticket(ticket, command).await?;
        Ok(ticket)
    }

    async fn one_end(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peers: [String; 2],
        cids: Cids,
    ) -> Result<(), NetworkError> {
        let role = me.as_bytes()[0];
        let conn = if role == b'c' {
            remote
                .register_with_defaults(
                    addr,
                    me.as_str(),
                    me.as_str(),
                    PASSWORD,
                    CertVerification::SelfSignedAccepted,
                )
                .await?;
            let conn = connect(&remote, &me).await?;
            wait_for_peers().await;
            wait_for_peers().await;
            conn
        } else {
            let peer = if role == b'a' { &peers[1] } else { &peers[0] };
            register_connect_and_befriend(&remote, addr, &me, peer).await?
        };
        if role != b'c' {
            let _ = cids[usize::from(role == b'b')].set(conn.cid);
        }
        wait_for_peers().await;
        let _channel = match role {
            b'a' => {
                let target = conn.find_target(conn.cid, peers[1].clone()).await?;
                let dial = target.connect_to_peer_custom(
                    settings(SecurityLevel::Standard),
                    UdpMode::Disabled,
                    None,
                );
                Some(channel_from(Some(dial), &mut events).await)
            }
            b'b' => {
                let offer = next_offer(&mut events).await;
                citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
                Some(channel_from(None::<std::future::Pending<_>>, &mut events).await)
            }
            _ => None,
        };
        wait_for_peers().await;
        let a = *cids[0].get().expect("a's cid");
        if role == b'c' {
            for signal in signals(conn.cid, a, "c") {
                let ticket = send(&remote, conn.cid, signal).await?;
                let (refused_on, why) = next_error(&mut events).await;
                assert_eq!(refused_on, ticket, "the refusal answers {ticket}");
                assert!(why.contains("not relayed"), "refused as: {why}");
            }
        }
        wait_for_peers().await;
        match role {
            b'b' => {
                let [webrtc, error] = signals(conn.cid, a, "b");
                let webrtc = send(&remote, conn.cid, webrtc).await?;
                send(&remote, conn.cid, error).await?;
                let (ticket, heard) = next_error(&mut events).await;
                assert_ne!(ticket, webrtc, "b's signalling to a was refused: {heard}");
                assert_eq!(heard, "from a", "b hears a's answer, not a refusal");
            }
            b'a' => {
                let (_, heard) = next_error(&mut events).await;
                assert_eq!(heard, "from b", "the first error to reach a is b's");
                let b = *cids[1].get().expect("b's cid");
                let [_, answer] = signals(conn.cid, b, "a");
                send(&remote, conn.cid, answer).await?;
            }
            _ => {}
        }
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn signalling_is_relayed_only_within_an_accepted_pair() {
        citadel_logging::setup_log();
        TestBarrier::setup(3);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let names = ["a", "b", "c"].map(|n| format!("{n}_{tag}"));
        let pair = [names[0].clone(), names[1].clone()];
        let cids: Cids = Arc::new([OnceLock::new(), OnceLock::new()]);
        let node = |me: String| {
            let (pair, cids) = (pair.clone(), cids.clone());
            citadel_sdk::test_common::node_builder()
                .with_link_manager(citadel_sdk::prelude::LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(remote, events, addr, me, pair, cids)
                }))
                .unwrap()
        };
        let [a, b, c] = names;
        let clients = futures::future::try_join3(node(a), node(b), node(c));
        let outcome = citadel_io::time::runnable_timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("only the accepted pair's signalling is relayed");
    }
}
