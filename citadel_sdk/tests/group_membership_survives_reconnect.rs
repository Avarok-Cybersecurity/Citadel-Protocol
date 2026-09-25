#![cfg(not(target_family = "wasm"))]
//! A group member that disconnects and reconnects must receive the group's
//! messages again, with nobody doing anything.
//!
//! The member's TreeKEM state lives in its session's state container, so a new
//! session starts with none. The server still lists the member in the group and
//! keeps forwarding broadcasts to it; the member's client used to drop every one
//! with "no CGKA state" while the owner was told the send succeeded. Only a
//! re-invite from the owner brought the member back.
//!
//! ```text
//! A, B: register → connect → mutual peer register
//! A: create group inviting B → B accepts → B's channel opens
//! A sends "before" → B receives it
//! B: disconnect → connect (same account, fresh session) → drop the dead channel
//! A sends "after-N" until B receives one; B must, within a timeout,
//!   without calling anything group-related after reconnecting
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use citadel_io::tokio::sync::{Barrier, Mutex};
    use citadel_sdk::async_trait;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// How long the member may take, after reconnecting, to be back in the group
    /// and receive a message. Generous for CI; the rejoin is one round trip
    /// through the relay to the owner and back.
    const REJOIN_DEADLINE: Duration = Duration::from_secs(30);
    const PASSWORD: &str = "password123";

    type Events = UnboundedReceiver<NodeResult<StackedRatchet>>;

    /// Hands the test body a receiver of every unsolicited event (invitations,
    /// group channels) so it can wait on them.
    struct GroupTestKernel<F> {
        handler: Mutex<Option<F>>,
        remote: Option<NodeRemote<StackedRatchet>>,
        events_tx: UnboundedSender<NodeResult<StackedRatchet>>,
        events_rx: Mutex<Option<Events>>,
    }

    impl<F> GroupTestKernel<F> {
        fn new(handler: F) -> Self {
            let (events_tx, events_rx) = unbounded_channel();
            Self {
                handler: Mutex::new(Some(handler)),
                remote: None,
                events_tx,
                events_rx: Mutex::new(Some(events_rx)),
            }
        }
    }

    #[async_trait]
    impl<F, Fut> NetKernel<StackedRatchet> for GroupTestKernel<F>
    where
        F: FnOnce(NodeRemote<StackedRatchet>, Events) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<(), NetworkError>> + Send,
    {
        fn load_remote(
            &mut self,
            node_remote: NodeRemote<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            self.remote = Some(node_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            let remote = self.remote.clone().expect("remote loaded before start");
            let handler = self.handler.lock().await.take().expect("started once");
            let events = self.events_rx.lock().await.take().expect("started once");
            handler(remote, events).await
        }

        async fn on_node_event_received(
            &self,
            message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            let _ = self.events_tx.send(message);
            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    async fn next_group_channel(events: &mut Events, deadline: Duration) -> GroupChannel {
        tokio::time::timeout(deadline, async {
            while let Some(evt) = events.recv().await {
                if let NodeResult::GroupChannelCreated(GroupChannelCreated { channel, .. }) = evt {
                    return channel;
                }
                log::info!(target: "citadel", "[member] event while waiting for a group channel: {evt:?}");
            }
            panic!("event stream ended before a group channel opened");
        })
        .await
        .expect("the member was not back in the group after reconnecting: no group channel opened")
    }

    async fn next_message_with_prefix(channel: &mut GroupChannel, prefix: &str) -> Vec<u8> {
        tokio::time::timeout(REJOIN_DEADLINE, async {
            loop {
                match channel.recv().await {
                    Some(GroupBroadcastPayload::Message { payload, .. })
                        if payload.as_ref().starts_with(prefix.as_bytes()) =>
                    {
                        return payload.as_ref().to_vec();
                    }
                    Some(other) => {
                        log::info!(target: "citadel", "[member] group payload while waiting for {prefix}: {other:?}")
                    }
                    None => panic!("group channel closed while waiting for {prefix}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the member received no '{prefix}' message within the deadline"))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_member_receives_group_messages_after_reconnecting() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let username_a = format!("gro_{}", &Uuid::new_v4().to_string()[..8]);
        let username_b = format!("grm_{}", &Uuid::new_v4().to_string()[..8]);

        let received_before = Arc::new(Barrier::new(2));
        let reconnected = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let member_got_after = Arc::new(AtomicBool::new(false));

        let owner = {
            let (username, peer) = (username_a.clone(), username_b.clone());
            let (received_before, reconnected, done) =
                (received_before.clone(), reconnected.clone(), done.clone());
            let member_got_after = member_got_after.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let reg = remote
                        .register_with_defaults(
                            server_addr,
                            username.as_str(),
                            username.as_str(),
                            PASSWORD,
                        )
                        .await?;
                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            PASSWORD,
                        ))
                        .await?;
                    wait_for_peers().await;
                    let status = conn
                        .propose_target(reg.cid, peer.clone())
                        .await?
                        .register_to_peer()
                        .await?;
                    assert!(
                        status.is_accepted(),
                        "owner's peer registration refused: {:?}",
                        status.refusal_reason()
                    );
                    wait_for_peers().await;

                    let channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    // The member's channel is open (so it is in the tree) before this send.
                    wait_for_peers().await;
                    channel
                        .send_message(SecBuffer::from(b"before".to_vec()))
                        .await?;
                    received_before.wait().await;

                    reconnected.wait().await;
                    // Keep sending until the member has one: the rejoin completes
                    // asynchronously, and a message sent before the member's Welcome
                    // lands cannot be decrypted by it.
                    let started = std::time::Instant::now();
                    let mut n = 0u32;
                    while !member_got_after.load(Ordering::SeqCst)
                        && started.elapsed() < REJOIN_DEADLINE + Duration::from_secs(5)
                    {
                        channel
                            .send_message(SecBuffer::from(format!("after-{n}").into_bytes()))
                            .await?;
                        n += 1;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (username, peer) = (username_b.clone(), username_a.clone());
            let (received_before, reconnected, done) =
                (received_before.clone(), reconnected.clone(), done.clone());
            let member_got_after = member_got_after.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let reg = remote
                        .register_with_defaults(
                            server_addr,
                            username.as_str(),
                            username.as_str(),
                            PASSWORD,
                        )
                        .await?;
                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            PASSWORD,
                        ))
                        .await?;
                    wait_for_peers().await;
                    let status = conn
                        .propose_target(reg.cid, peer.clone())
                        .await?
                        .register_to_peer()
                        .await?;
                    assert!(
                        status.is_accepted(),
                        "member's peer registration refused: {:?}",
                        status.refusal_reason()
                    );
                    wait_for_peers().await;

                    // Accept the invitation, then wait for the channel.
                    let invitation = tokio::time::timeout(REJOIN_DEADLINE, async {
                        loop {
                            match events.recv().await {
                                Some(
                                    evt @ NodeResult::GroupEvent(GroupEvent {
                                        event: GroupBroadcast::Invitation { .. },
                                        ..
                                    }),
                                ) => return evt,
                                Some(_) => continue,
                                None => panic!("event stream ended before the invitation"),
                            }
                        }
                    })
                    .await
                    .expect("no group invitation arrived");
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut first_channel = next_group_channel(&mut events, REJOIN_DEADLINE).await;
                    wait_for_peers().await;
                    let before = next_message_with_prefix(&mut first_channel, "before").await;
                    assert_eq!(before, b"before");
                    received_before.wait().await;

                    // The channel is NOT dropped first: dropping a live channel is an
                    // explicit LeaveRoom. A member losing its session keeps its channel
                    // until it notices, as the agent does.
                    conn.disconnect().await?;
                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            PASSWORD,
                        ))
                        .await?;
                    assert_eq!(conn.cid, reg.cid, "CID is permanent per account");
                    // Discarding the dead session's channel after reconnecting must not
                    // take the member out of the group from its new session.
                    drop(first_channel);
                    reconnected.wait().await;

                    // Nothing group-related is called from here on: the member must be
                    // put back in the group by the protocol itself.
                    let mut channel = next_group_channel(&mut events, REJOIN_DEADLINE).await;
                    let after = next_message_with_prefix(&mut channel, "after-").await;
                    log::info!(target: "citadel", "[member] received {:?} after reconnecting", String::from_utf8_lossy(&after));
                    member_got_after.store(true, Ordering::SeqCst);
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();

        let clients = async move { futures::future::try_join(owner, member).await.map(|_| ()) };
        let task = async move {
            tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res,
            }
        };

        let result = tokio::time::timeout(Duration::from_secs(150), task)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");
        assert!(member_got_after.load(Ordering::SeqCst));
    }
}
