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
    async fn a_member_receives_group_messages_after_reconnecting() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let owner_name = format!("gro_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("grm_{}", &Uuid::new_v4().to_string()[..8]);
        let received_before = Arc::new(Barrier::new(2));
        let reconnected = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let member_got_after = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (received_before, reconnected, done) =
                (received_before.clone(), reconnected.clone(), done.clone());
            let member_got_after = member_got_after.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    // The member's channel is open (so it is in the tree) before this send.
                    wait_for_peers().await;
                    channel
                        .send_message(SecBuffer::from(b"before".to_vec()))
                        .await?;
                    received_before.wait().await;

                    reconnected.wait().await;
                    send_until(&channel, "after", &member_got_after).await?;
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
            let member_got_after = member_got_after.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut first_channel = next_group_channel(&mut events, "member").await;
                    wait_for_peers().await;
                    assert_eq!(
                        next_message_with_prefix(&mut first_channel, "before").await,
                        b"before"
                    );
                    received_before.wait().await;

                    // The channel is NOT dropped first: dropping a live channel is an
                    // explicit LeaveRoom. A member losing its session keeps its channel
                    // until it notices, as the agent does.
                    let cid = conn.cid;
                    conn.disconnect().await?;
                    let conn = connect(&remote, &me).await?;
                    assert_eq!(conn.cid, cid, "CID is permanent per account");
                    // Discarding the dead session's channel after reconnecting must not
                    // take the member out of the group from its new session.
                    drop(first_channel);
                    reconnected.wait().await;

                    // Nothing group-related is called from here on: the member must be
                    // put back in the group by the protocol itself.
                    let mut channel = next_group_channel(&mut events, "member").await;
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
        run_pair(server, owner, member).await;
        assert!(member_got_after.load(Ordering::SeqCst));
    }
}
