#![cfg(not(target_family = "wasm"))]
//! A group OWNER that disconnects and reconnects keeps its group.
//!
//! The server used to delete every group an owner held the moment the owner's
//! session ended, so an agent restart or a network drop destroyed every group,
//! for the owner and every member, with nothing telling anyone. The owner's
//! TreeKEM state dies with its session as well, so keeping the server record is
//! not enough: the owner has to re-found the tree and the members rejoin it.
//!
//! ```text
//! A (owner), B: register → connect → mutual peer register
//! A: create group inviting B → B accepts → A sends "before" → B receives it
//! A: disconnect → connect (fresh session) → drop the dead channel
//! A must get a group channel back without asking; A sends "after-N" until
//!   B receives one on the channel B never closed; then B sends "reply-N"
//!   until A receives one
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_owner_keeps_its_group_across_a_reconnect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let owner_name = format!("goo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gom_{}", &Uuid::new_v4().to_string()[..8]);
        let received_before = Arc::new(Barrier::new(2));
        let reconnected = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let member_got_after = Arc::new(AtomicBool::new(false));
        let owner_got_reply = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (received_before, reconnected, done) =
                (received_before.clone(), reconnected.clone(), done.clone());
            let (member_got_after, owner_got_reply) =
                (member_got_after.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let first_channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    let key = first_channel.key();
                    wait_for_peers().await;
                    first_channel
                        .send_message(SecBuffer::from(b"before".to_vec()))
                        .await?;
                    received_before.wait().await;

                    // Not dropped first: that is an explicit LeaveRoom, not a lost session.
                    conn.disconnect().await?;
                    let conn = connect(&remote, &me).await?;
                    drop(first_channel);
                    reconnected.wait().await;

                    // Nothing group-related is called from here on.
                    let mut channel = next_group_channel(&mut events, "owner").await;
                    assert_eq!(channel.key(), key, "the owner gets the same group back");
                    send_until(&channel, "after", &member_got_after).await?;
                    let reply = next_message_with_prefix(&mut channel, "reply-").await;
                    log::info!(target: "citadel", "[owner] received {:?} after reconnecting", String::from_utf8_lossy(&reply));
                    owner_got_reply.store(true, Ordering::SeqCst);
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (received_before, reconnected, done) =
                (received_before.clone(), reconnected.clone(), done.clone());
            let (member_got_after, owner_got_reply) =
                (member_got_after.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "member").await;
                    wait_for_peers().await;
                    assert_eq!(
                        next_message_with_prefix(&mut channel, "before").await,
                        b"before"
                    );
                    received_before.wait().await;
                    reconnected.wait().await;

                    // The member never reconnected and keeps the channel it had.
                    let after = next_message_with_prefix(&mut channel, "after-").await;
                    log::info!(target: "citadel", "[member] received {:?} after the owner reconnected", String::from_utf8_lossy(&after));
                    member_got_after.store(true, Ordering::SeqCst);
                    send_until(&channel, "reply", &owner_got_reply).await?;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();
        run_pair(server, owner, member).await;
        assert!(member_got_after.load(Ordering::SeqCst));
        assert!(owner_got_reply.load(Ordering::SeqCst));
    }
}
