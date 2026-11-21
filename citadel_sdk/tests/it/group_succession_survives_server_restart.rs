#![cfg(not(target_family = "wasm"))]
//! A group's new owner is still its owner after the server restarts, and acts as one.
//!
//! ```text
//! O and M befriend; O creates a group inviting M; M joins
//! O leaves; M is told it owns the group
//! the server restarts over the same backend; O and M reconnect
//! M gets its group back as its owner; O owns nothing
//! M invites O back; O joins and reads M's "after-restart"
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::client_node;
    use crate::common::group_succession::*;
    use crate::common::server_restart::{listener_at, restarting_server};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_new_owner_keeps_its_group_across_a_server_restart() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let backend_dir = std::env::temp_dir().join(format!("citadel-gss-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&backend_dir).unwrap();
        let listener = listener_at("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = listener.local_addr().unwrap();
        let owner_name = format!("gro_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("grm_{}", &Uuid::new_v4().to_string()[..8]);
        // Three parties: the two clients and the server orchestration.
        let ready_for_restart = Arc::new(Barrier::new(3));
        let server_back = Arc::new(Barrier::new(3));
        let sync = Arc::new(Barrier::new(2));
        let owner_cid = Arc::new(AtomicU64::new(0));
        let rejoined_read = Arc::new(AtomicBool::new(false));

        let server = restarting_server(
            listener,
            backend_dir.clone(),
            ready_for_restart.clone(),
            server_back.clone(),
        );

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (ready_for_restart, server_back, sync) =
                (ready_for_restart.clone(), server_back.clone(), sync.clone());
            let (owner_cid, rejoined_read) = (owner_cid.clone(), rejoined_read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    owner_cid.store(conn.cid, Ordering::SeqCst);
                    let mut first = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    wait_for_peers().await; // joined
                    assert!(leave(&mut first).await?, "the owner's leave was refused");
                    sync.wait().await; // ownership passed
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "owner").await;
                    let conn = reconnect(&remote, &me).await?;
                    drop(first);
                    assert!(
                        conn.list_owned_groups().await?.is_empty(),
                        "the owner that left owns its group again after the restart"
                    );
                    sync.wait().await; // both back

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "owner").await;
                    let read = next_message_with_prefix(&mut channel, "after-restart").await;
                    rejoined_read.store(!read.is_empty(), Ordering::SeqCst);
                    sync.wait().await; // test over
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (ready_for_restart, server_back, sync) =
                (ready_for_restart.clone(), server_back.clone(), sync.clone());
            let (owner_cid, rejoined_read) = (owner_cid.clone(), rejoined_read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut first = next_group_channel(&mut events, "member").await;
                    let key = first.key();
                    wait_for_peers().await; // joined
                    assert_eq!(ownership_transferred(&mut first).await, conn.cid);
                    sync.wait().await; // ownership passed
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "member").await;
                    let conn = reconnect(&remote, &me).await?;
                    drop(first);
                    let channel = next_group_channel(&mut events, "member").await;
                    assert_eq!(channel.key(), key, "the new owner gets the same group back");
                    assert_eq!(channel.owner(), Some(conn.cid));
                    assert_eq!(conn.list_owned_groups().await?, vec![key]);
                    sync.wait().await; // both back

                    channel.invite(owner_cid.load(Ordering::SeqCst)).await?;
                    send_until(&channel, "after-restart", &rejoined_read).await?;
                    sync.wait().await; // test over
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let _ = std::fs::remove_dir_all(&backend_dir);
        assert!(
            rejoined_read.load(Ordering::SeqCst),
            "a member the new owner invited after the restart did not read the group"
        );
    }
}
