#![cfg(not(target_family = "wasm"))]
//! A peer that accepts a dial and at once dials back must leave BOTH ends with a channel.
//!
//! The workspace agent accepts every inbound request and dials every wanted peer, so a newly
//! registered pair always dials in both directions. In the losing order the lower CID's dial is
//! accepted first, it sends Stage0, and only then does the higher CID's own dial reach it. The
//! lower CID used to take that dial for a simultaneous connect and auto-accept it, replacing the
//! exchange it had just started with an empty slot; the higher CID, already answering that
//! exchange as bob, then dropped the auto-accept's second exchange (first exchange wins). Each end
//! waited for the other's exchange and neither got a channel (workspace PR 255, call-group spec
//! "A and B connect": A's sends were accepted, B never heard them).
//!
//! The roles are fixed by CID so the losing order is the one exercised: the lower CID dials, the
//! higher CID accepts that dial and immediately dials back.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use futures::StreamExt;
    use std::time::Duration;

    /// Under the SDK's own 60s dial bound, so a dead exchange fails here rather than there.
    const CHANNEL_DEADLINE: Duration = Duration::from_secs(30);
    const MESSAGE_DEADLINE: Duration = Duration::from_secs(20);

    /// How one end came by its channel, for the failure message.
    struct Outcome {
        channel: Option<PeerChannel<StackedRatchet>>,
        dial: Option<Result<(), String>>,
        inbound_channels: usize,
    }

    async fn accept(signal: PeerSignal, remote: &NodeRemote<StackedRatchet>) {
        responses::peer_connect(signal, true, remote, None)
            .await
            .expect("accept sent");
    }

    /// Waits for the peer's dial and accepts it.
    async fn accept_first_offer(events: &mut Events, remote: &NodeRemote<StackedRatchet>) {
        while let Some(event) = events.recv().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    signal @ PeerSignal::PostConnect {
                        invitee_response: None,
                        ..
                    },
                ..
            }) = event
            {
                return accept(signal, remote).await;
            }
        }
        panic!("the event stream ended before the peer dialled");
    }

    /// Dials `peer` while accepting every inbound request, until a channel exists -- the dial's,
    /// or the one an accepted exchange created -- or the deadline passes.
    async fn dial_while_accepting(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        remote: &NodeRemote<StackedRatchet>,
        events: &mut Events,
        peer: &str,
    ) -> Outcome {
        let dial = async {
            conn.find_target(conn.cid, peer.to_string())
                .await?
                .connect_to_peer_custom(Default::default(), UdpMode::Enabled, None)
                .await
        };
        tokio::pin!(dial);
        let mut outcome = Outcome {
            channel: None,
            dial: None,
            inbound_channels: 0,
        };
        let _ = tokio::time::timeout(CHANNEL_DEADLINE, async {
            while outcome.channel.is_none() {
                tokio::select! {
                    result = &mut dial, if outcome.dial.is_none() => match result {
                        Ok(success) => {
                            outcome.dial = Some(Ok(()));
                            outcome.channel = Some(success.channel);
                        }
                        Err(err) => outcome.dial = Some(Err(err.to_string())),
                    },
                    event = events.recv() => match event {
                        Some(NodeResult::PeerEvent(PeerEvent {
                            event: signal @ PeerSignal::PostConnect { invitee_response: None, .. },
                            ..
                        })) => accept(signal, remote).await,
                        Some(NodeResult::PeerChannelCreated(created)) => {
                            outcome.inbound_channels += 1;
                            outcome.channel = Some(*created.channel);
                        }
                        Some(_) => {}
                        None => return,
                    },
                }
            }
        })
        .await;
        outcome
    }

    async fn one_end(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let peer_cid = conn
            .find_target(conn.cid, peer.clone())
            .await?
            .try_as_peer_connection()
            .await?
            .get_original_target_cid();
        wait_for_peers().await;
        if conn.cid > peer_cid {
            accept_first_offer(&mut events, &remote).await;
        }
        let outcome = dial_while_accepting(&conn, &remote, &mut events, &peer).await;
        let role = if conn.cid > peer_cid {
            "accepted, then dialled back"
        } else {
            "dialled first"
        };
        let report = format!(
            "{me} ({role}): dial answered {:?}, inbound channels {}",
            outcome.dial, outcome.inbound_channels
        );
        let channel = outcome.channel.unwrap_or_else(|| {
            panic!("{report}; no channel to {peer} within {CHANNEL_DEADLINE:?}")
        });
        let (mut tx, mut rx) = channel.split();
        tx.send(SecBuffer::from(format!("hello from {me}").as_bytes()))
            .await
            .unwrap_or_else(|err| panic!("{report}; send failed: {err}"));
        let received = tokio::time::timeout(MESSAGE_DEADLINE, rx.next())
            .await
            .unwrap_or_else(|_| panic!("{report}; nothing from {peer} within {MESSAGE_DEADLINE:?}"))
            .unwrap_or_else(|| panic!("{report}; the channel from {peer} closed"));
        assert_eq!(
            received.as_ref(),
            format!("hello from {peer}").as_bytes(),
            "{report}"
        );
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dial_back_during_the_first_exchange_connects_both_ends() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));

        let node = |me: String, peer: String| {
            DefaultNodeBuilder::default()
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .build(GroupTestKernel::new(
                    move |remote: NodeRemote<StackedRatchet>, events: Events| {
                        one_end(remote, events, addr, me, peer)
                    },
                ))
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
        outcome.expect("both ends hold a working channel");
    }
}
