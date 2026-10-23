#![cfg(not(target_family = "wasm"))]
//! A member who asks to join a private group, and whom the owner accepts, is sent the group's key:
//! it publishes its KeyPackage, receives its Welcome, opens the group channel, and messages flow
//! both ways.
//!
//! The server answered the owner's `AcceptMembership` only to the owner. On the invitation path
//! the one accepting is the joiner, so that answer is what starts its KeyPackage; on the
//! request path the joiner heard only `MemberStateChanged`, published nothing, and stayed a
//! member the server relays to who can decrypt nothing ("this session holds no key for the group
//! yet"). App topics (owner-accepted, private) are exactly that path.
//!
//! ```text
//! A, B: register → connect → befriend; A creates a private group inviting nobody
//! B sends RequestJoin; A receives it and sends AcceptMembership { target: B }
//! B's group channel opens; A → B and B → A messages arrive
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use uuid::Uuid;

    /// The owner hears a join request on its group channel (the protocol forwards a group's
    /// signals to the channel open for it).
    async fn next_join_request(channel: &mut GroupChannel) -> u64 {
        tokio::time::timeout(REJOIN_DEADLINE, async {
            loop {
                match channel.recv().await {
                    Some(GroupBroadcastPayload::Event {
                        payload: GroupBroadcast::RequestJoin { sender, .. },
                    }) => return sender,
                    Some(_) => continue,
                    None => panic!("the group channel closed before the join request"),
                }
            }
        })
        .await
        .expect("the owner never received the join request")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_accepted_join_receives_its_welcome() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("acc_o_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("acc_m_{}", &Uuid::new_v4().to_string()[..8]);
        let group: Arc<OnceLock<MessageGroupKey>> = Arc::new(OnceLock::new());
        let created = Arc::new(Barrier::new(2));
        let owner_heard = Arc::new(AtomicBool::new(false));
        let member_heard = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (group, created) = (group.clone(), created.clone());
            let (owner_heard, member_heard) = (owner_heard.clone(), member_heard.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let mut channel = conn
                        .create_group_with_options(None, MessageGroupOptions::default())
                        .await?;
                    let _ = group.set(channel.key());
                    created.wait().await;

                    let joiner = next_join_request(&mut channel).await;
                    let key = channel.key();
                    remote
                        .send(NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
                            session_cid: conn.cid,
                            command: GroupBroadcast::AcceptMembership {
                                target: joiner,
                                key,
                            },
                        }))
                        .await?;

                    // B's messages first (B cannot send without its key), then A's.
                    let heard = next_message_with_prefix(&mut channel, "from-member").await;
                    assert!(!heard.is_empty());
                    owner_heard.store(true, Ordering::SeqCst);
                    send_until(&channel, "from-owner", &member_heard).await?;
                    wait_for_peers().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (group, created) = (group.clone(), created.clone());
            let (owner_heard, member_heard) = (owner_heard.clone(), member_heard.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    created.wait().await;
                    let key = *group.get().expect("the owner created the group first");
                    let mut asked = remote
                        .send_callback_subscription(NodeRequest::GroupBroadcastCommand(
                            GroupBroadcastCommand {
                                session_cid: conn.cid,
                                command: GroupBroadcast::RequestJoin {
                                    sender: conn.cid,
                                    key,
                                },
                            },
                        ))
                        .await?;
                    let pending = tokio::time::timeout(REJOIN_DEADLINE, asked.next())
                        .await
                        .expect("the server never answered the join request");
                    assert!(
                        matches!(
                            pending,
                            Some(NodeResult::GroupEvent(GroupEvent {
                                event: GroupBroadcast::RequestJoinPending { result: Ok(()), .. },
                                ..
                            }))
                        ),
                        "a private group relays the request to its owner: {pending:?}"
                    );

                    let mut channel = next_group_channel(&mut events, &me).await;
                    assert_eq!(channel.key(), key);
                    send_until(&channel, "from-member", &owner_heard).await?;
                    let heard = next_message_with_prefix(&mut channel, "from-owner").await;
                    assert!(!heard.is_empty());
                    member_heard.store(true, Ordering::SeqCst);
                    wait_for_peers().await;
                    drop(channel);
                    remote.shutdown().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(owner)
            .unwrap();
        let member = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(member)
            .unwrap();
        run_pair(server, owner, member).await;
    }
}
