#![cfg(not(target_family = "wasm"))]
//! An ephemeral group's broadcasts reach only the members online when they are sent: the server
//! mails none to an offline member. An ordinary group still mails them, as it always has.
//!
//! ```text
//! A, B: register → connect → befriend; A creates a group (ephemeral or not) inviting B
//! B joins, then disconnects; A waits until the server holds no session for B
//! A sends "while-away" and waits for the server's answer
//! the server's mailbox for B holds that message for an ordinary group, and nothing for an
//!   ephemeral one
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// How many copies of a message sent while the member was offline the server mailed it.
    async fn mailed_while_away(ephemeral: bool) -> usize {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = probed_server();
        let owner_name = format!("eph_o_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("eph_m_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let member_away = Arc::new(Barrier::new(2));
        let mailed = Arc::new(AtomicUsize::new(usize::MAX));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (member_cid, member_away, mailed) =
                (member_cid.clone(), member_away.clone(), mailed.clone());
            let server_remote = server_remote.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let options = MessageGroupOptions {
                        ephemeral,
                        ..Default::default()
                    };
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), options).await?;
                    member_away.wait().await;
                    let server = server_of(&server_remote);
                    let member = member_cid.load(Ordering::SeqCst);
                    until_offline(server, member).await;

                    channel
                        .send_message(SecBuffer::from(b"while-away".to_vec()))
                        .await?;
                    let answer = next_send_answer(&mut channel).await;
                    assert!(
                        matches!(answer, GroupBroadcast::MessageResponse { .. }),
                        "an offline member is not a refusal: {answer:?}"
                    );
                    let count = mailed_group_messages(server, member, channel.key()).await;
                    mailed.store(count, Ordering::SeqCst);
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (member_cid, member_away) = (member_cid.clone(), member_away.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    conn.disconnect().await?;
                    member_away.wait().await;
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
        mailed.load(Ordering::SeqCst)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_ephemeral_group_mails_nothing_to_an_offline_member() {
        assert_eq!(mailed_while_away(true).await, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_ordinary_group_still_mails_an_offline_member() {
        assert_eq!(mailed_while_away(false).await, 1);
    }
}
