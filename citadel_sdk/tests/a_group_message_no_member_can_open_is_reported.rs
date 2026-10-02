#![cfg(not(target_family = "wasm"))]
//! A flat-group message the receiver cannot decrypt reaches its application as `MessageDropped`,
//! not as nothing.
//!
//! A Commit that removes a member clears every earlier epoch's key (post-compromise security), so
//! a message another member sealed before applying that Commit can no longer be opened by anyone
//! who has. The receiver used to drop it at TRACE level: a lost message nobody was told about.
//!
//! ```text
//! O creates a group with A and C; once both are in, A holds every Commit it receives
//! O kicks C → the removal Commit reaches A and is held
//! A: sends "a-old", sealed at the epoch before the removal; the server relays it
//! A: releases and applies the Commit, then sends "a-new"
//! O must see MessageDropped from A, then "a-new"
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::hold_inbound_commits;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    const UNSET: u64 = u64::MAX;

    #[derive(Default)]
    struct Shared {
        a_cid: AtomicU64,
        c_cid: AtomicU64,
        /// What the owner saw from A, in order, up to and including "a-new".
        owner_saw: Mutex<Vec<String>>,
    }

    async fn befriend(
        conn: &CitadelClientServerConnection<StackedRatchet>,
        cid: u64,
        me: &str,
        peer: &str,
    ) -> Result<(), NetworkError> {
        let status = conn
            .propose_target(cid, peer.to_string())
            .await?
            .register_to_peer()
            .await?;
        assert!(
            status.is_accepted(),
            "{me} → {peer}: peer registration refused"
        );
        Ok(())
    }

    /// Register, connect, befriend the owner in this member's turn, and join the group.
    #[allow(clippy::too_many_arguments)]
    async fn member(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        server_addr: std::net::SocketAddr,
        me: String,
        owner: String,
        cid_cell: &AtomicU64,
        befriends_first: bool,
        sync: &Barrier,
    ) -> Result<(CitadelClientServerConnection<StackedRatchet>, GroupChannel), NetworkError> {
        let reg = remote
            .register_with_defaults(server_addr, &me, &me, PASSWORD)
            .await?;
        cid_cell.store(reg.cid, Ordering::SeqCst);
        let conn = connect(&remote, &me).await?;
        sync.wait().await;
        if !befriends_first {
            sync.wait().await;
        }
        befriend(&conn, reg.cid, &me, &owner).await?;
        sync.wait().await;
        if befriends_first {
            sync.wait().await;
        }
        let invitation = next_invitation(&mut events).await;
        let _ = responses::group_invite(invitation, true, &remote).await?;
        let channel = next_group_channel(&mut events, &me).await;
        sync.wait().await; // A and C are in the group
        Ok((conn, channel))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_message_sealed_before_a_removal_commit_is_reported_as_dropped() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let tag = &Uuid::new_v4().to_string()[..8];
        let o_name = format!("mdo_{tag}");
        let a_name = format!("mda_{tag}");
        let c_name = format!("mdc_{tag}");
        let sync = Arc::new(Barrier::new(3));
        let shared = Arc::new(Shared::default());
        shared.a_cid.store(UNSET, Ordering::SeqCst);
        shared.c_cid.store(UNSET, Ordering::SeqCst);

        let owner = {
            let (me, a, c, sync, shared) = (
                o_name.clone(),
                a_name.clone(),
                c_name.clone(),
                sync.clone(),
                shared.clone(),
            );
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let reg = remote
                        .register_with_defaults(server_addr, &me, &me, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &a).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &c).await?;
                    sync.wait().await;

                    let mut channel = conn
                        .create_group(Some(vec![a.clone().into(), c.clone().into()]))
                        .await?;
                    sync.wait().await; // A and C are in the group
                    sync.wait().await; // A holds its Commits
                    let a_cid = shared.a_cid.load(Ordering::SeqCst);
                    channel.kick(shared.c_cid.load(Ordering::SeqCst)).await?;

                    loop {
                        match channel.recv().await {
                            Some(GroupBroadcastPayload::Message { payload, sender })
                                if sender == a_cid =>
                            {
                                let text = String::from_utf8_lossy(payload.as_ref()).to_string();
                                let done = text == "a-new";
                                shared.owner_saw.lock().unwrap().push(text);
                                if done {
                                    break;
                                }
                            }
                            Some(GroupBroadcastPayload::Event {
                                payload: GroupBroadcast::MessageDropped { sender, reason, .. },
                            }) if sender == a_cid => {
                                shared
                                    .owner_saw
                                    .lock()
                                    .unwrap()
                                    .push(format!("MessageDropped: {reason}"));
                            }
                            Some(_) => {}
                            None => panic!("the owner's group channel closed"),
                        }
                    }
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_a = {
            let (me, o, sync, shared) =
                (a_name.clone(), o_name.clone(), sync.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, events: Events| async move {
                    let (conn, mut channel) = member(
                        remote,
                        events,
                        server_addr,
                        me,
                        o,
                        &shared.a_cid,
                        true,
                        &sync,
                    )
                    .await?;
                    let mut hold = hold_inbound_commits(shared.a_cid.load(Ordering::SeqCst));
                    sync.wait().await; // A holds its Commits

                    hold.arrived().await;
                    channel
                        .send_message(SecBuffer::from(b"a-old".to_vec()))
                        .await?;
                    loop {
                        match channel.recv().await {
                            Some(GroupBroadcastPayload::Event {
                                payload: GroupBroadcast::MessageResponse { success, .. },
                            }) => {
                                assert!(success, "the server could not relay a-old");
                                break;
                            }
                            Some(_) => {}
                            None => panic!("A's group channel closed"),
                        }
                    }
                    hold.release().await;
                    channel
                        .send_message(SecBuffer::from(b"a-new".to_vec()))
                        .await?;
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_c = {
            let (me, o, sync, shared) =
                (c_name.clone(), o_name.clone(), sync.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, events: Events| async move {
                    let (conn, channel) = member(
                        remote,
                        events,
                        server_addr,
                        me,
                        o,
                        &shared.c_cid,
                        false,
                        &sync,
                    )
                    .await?;
                    sync.wait().await; // A holds its Commits
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member_a = DefaultNodeBuilder::default().build(member_a).unwrap();
        let member_c = DefaultNodeBuilder::default().build(member_c).unwrap();
        let clients = async move { futures::future::try_join3(owner, member_a, member_c).await };
        let task = async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(240), task)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");

        let saw = shared.owner_saw.lock().unwrap().clone();
        log::warn!(target: "citadel", "the owner saw from A: {saw:?}");
        assert!(
            saw.len() == 2 && saw[0].starts_with("MessageDropped") && saw[1] == "a-new",
            "a message A sealed before the removal Commit was lost without a MessageDropped: \
             the owner saw {saw:?}"
        );
    }
}
