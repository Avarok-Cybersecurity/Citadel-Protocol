#![cfg(not(target_family = "wasm"))]
//! A group survives a restart of the SERVER, not only of its clients.
//!
//! The server's group registry (owner → groups, members, retention holds) lived only in memory.
//! A Durable Object reset or any server restart therefore destroyed every group silently: both
//! clients reconnected by themselves, the restore protocol had nothing to restore from, and group
//! messages reached nobody with no error at either end. The registry is now kept in the server's
//! account backend and loaded when the server starts.
//!
//! ```text
//! A (owner), B: register → connect → mutual peer register (server v1, filesystem backend)
//! A: create group inviting B → B accepts → A sends "before" → B receives it
//! server v1 shuts down; server v2 starts on the same address over the same backend directory
//! A, B: reconnect (credentials only; nothing group-related is called)
//! A and B must each get a group channel back; A sends "after-N" until B receives one;
//!   B sends "reply-N" until A receives one
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::server_restart::{listener_at, restarting_server};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_group_survives_a_server_restart() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let backend_dir = std::env::temp_dir().join(format!("citadel-gsr-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&backend_dir).unwrap();
        let listener = listener_at("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = listener.local_addr().unwrap();

        let owner_name = format!("gso_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gsm_{}", &Uuid::new_v4().to_string()[..8]);
        // Three parties: the two clients and the server orchestration below.
        let ready_for_restart = Arc::new(Barrier::new(3));
        let server_back = Arc::new(Barrier::new(3));
        let done = Arc::new(Barrier::new(2));
        let member_got_after = Arc::new(AtomicBool::new(false));
        let owner_got_reply = Arc::new(AtomicBool::new(false));

        let server = restarting_server(
            listener,
            backend_dir.clone(),
            ready_for_restart.clone(),
            server_back.clone(),
        );

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (ready_for_restart, server_back, done) =
                (ready_for_restart.clone(), server_back.clone(), done.clone());
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
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "owner").await;
                    let conn = reconnect(&remote, &me).await?;
                    log::info!(target: "citadel", "[owner] reconnected to the restarted server");
                    drop(first_channel);

                    // Nothing group-related is called from here on.
                    let mut channel = next_group_channel(&mut events, "owner").await;
                    assert_eq!(channel.key(), key, "the owner gets the same group back");
                    send_until(&channel, "after", &member_got_after).await?;
                    let reply = next_message_with_prefix(&mut channel, "reply-").await;
                    log::info!(target: "citadel", "[owner] received {:?} after the server restart", String::from_utf8_lossy(&reply));
                    owner_got_reply.store(true, Ordering::SeqCst);
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (ready_for_restart, server_back, done) =
                (ready_for_restart.clone(), server_back.clone(), done.clone());
            let (member_got_after, owner_got_reply) =
                (member_got_after.clone(), owner_got_reply.clone());
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
                    let cid = conn.cid;
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "member").await;
                    let conn = reconnect(&remote, &me).await?;
                    log::info!(target: "citadel", "[member] reconnected to the restarted server");
                    assert_eq!(conn.cid, cid, "CID is permanent per account");
                    drop(first_channel);

                    let mut channel = next_group_channel(&mut events, "member").await;
                    let after = next_message_with_prefix(&mut channel, "after-").await;
                    log::info!(target: "citadel", "[member] received {:?} after the server restart", String::from_utf8_lossy(&after));
                    member_got_after.store(true, Ordering::SeqCst);
                    send_until(&channel, "reply", &owner_got_reply).await?;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(owner)
            .unwrap();
        let member = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(member)
            .unwrap();
        run_pair(server, owner, member).await;
        let _ = std::fs::remove_dir_all(&backend_dir);
        assert!(member_got_after.load(Ordering::SeqCst));
        assert!(owner_got_reply.load(Ordering::SeqCst));
    }
}
