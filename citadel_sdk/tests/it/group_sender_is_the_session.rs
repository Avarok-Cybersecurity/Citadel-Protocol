#![cfg(not(target_family = "wasm"))]
//! A group message reaches its members as sent by the session that sent it, whatever sender
//! the sending client wrote into the message.
//!
//! ```text
//! A, B: register → connect → befriend; A creates a group inviting B; B joins
//! A sends "claimed" through a raw group command whose sender names another cid
//! B must read "claimed" as sent by A
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// The sender A's client claims instead of its own cid.
    const CLAIMED: u64 = 4242;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_is_attributed_to_the_session_that_sent_it() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("gco_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gcm_{}", &Uuid::new_v4().to_string()[..8]);
        let owner_cid = Arc::new(AtomicU64::new(0));
        let attributed = Arc::new(AtomicU64::new(0));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let owner_cid = owner_cid.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, channel) = open_group(
                        &remote,
                        server_addr,
                        (&me, &peer),
                        MessageGroupOptions::default(),
                    )
                    .await?;
                    owner_cid.store(conn.cid, Ordering::SeqCst);
                    let command = GroupBroadcast::Message {
                        sender: CLAIMED,
                        key: channel.key(),
                        id: GroupMessageId::random(),
                        message: SecBuffer::from(b"claimed".to_vec()),
                    };
                    let _ = remote
                        .send(NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
                            session_cid: conn.cid,
                            command,
                        }))
                        .await?;
                    citadel_sdk::test_common::wait_for_peers().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let attributed = attributed.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    let sender = tokio::time::timeout(REJOIN_DEADLINE, async {
                        loop {
                            match channel.recv().await {
                                Some(GroupBroadcastPayload::Message { payload, sender, .. })
                                    if payload.as_ref() == b"claimed" =>
                                {
                                    return sender
                                }
                                Some(_) => continue,
                                None => panic!("the member's group channel closed"),
                            }
                        }
                    })
                    .await
                    .expect("the member never read the message");
                    attributed.store(sender, Ordering::SeqCst);
                    citadel_sdk::test_common::wait_for_peers().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        assert_eq!(
            attributed.load(Ordering::SeqCst),
            owner_cid.load(Ordering::SeqCst),
            "the member attributed the message to a cid other than its sender's"
        );
    }
}
