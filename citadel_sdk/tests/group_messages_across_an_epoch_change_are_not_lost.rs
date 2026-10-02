#![cfg(not(target_family = "wasm"))]
//! A member's group messages are not lost when another member joins while it is sending.
//!
//! Every join is a CGKA epoch change. A member sending while a join is in flight seals at the
//! old epoch until it applies the owner's Commit. The owner keeps the old epoch readable, and
//! holds the joiner's Welcome until every member has applied the Commit, so that nothing sealed
//! at the old epoch reaches the joiner after its channel opens (#321, #327).
//!
//! ```text
//! O, A, B: register → connect; O ↔ A and O ↔ B peer register
//! O: create a group inviting A → A accepts
//! A: sends "a-N" continuously
//! O: after reading 20 of them, invites B → B accepts → B's channel opens
//! A: sends 200 more after it sees B's channel open, then stops
//! O must read every "a-N" A sent; B must read every one A sent after its channel opened
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// How many of A's messages the owner reads before it invites B, so the join lands while A
    /// is already streaming at the settled epoch.
    const READ_BEFORE_INVITE: usize = 20;
    /// How many messages A sends after B's channel is open.
    const SENT_AFTER_JOIN: u64 = 200;
    /// Safety bound so a bug cannot make A send for ever.
    const SEND_CAP: u64 = 20_000;

    #[derive(Default)]
    struct Shared {
        b_cid: AtomicU64,
        b_joined: AtomicBool,
        reads: Reads,
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_members_messages_survive_another_member_joining() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let tag = &Uuid::new_v4().to_string()[..8];
        let o_name = format!("geo_{tag}");
        let a_name = format!("gea_{tag}");
        let b_name = format!("geb_{tag}");
        let sync = Arc::new(Barrier::new(3));
        let shared = Arc::new(Shared::default());
        let a_cid_cell = Arc::new(AtomicU64::new(UNSET));

        let owner = {
            let (me, a, b, sync, shared, a_cid_cell) = (
                o_name.clone(),
                a_name.clone(),
                b_name.clone(),
                sync.clone(),
                shared.clone(),
                a_cid_cell.clone(),
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
                    befriend(&conn, reg.cid, &me, &b).await?;
                    sync.wait().await;

                    let mut channel = conn.create_group(Some(vec![a.clone().into()])).await?;
                    sync.wait().await; // A's channel is open
                    let a_cid = a_cid_cell.load(Ordering::SeqCst);

                    // Read until A is streaming at the settled epoch, then add B mid-stream.
                    let mut read = 0usize;
                    while read < READ_BEFORE_INVITE {
                        if let Some(GroupBroadcastPayload::Message { payload, sender }) =
                            channel.recv().await
                        {
                            if sender == a_cid {
                                if let Some(idx) = parse_idx(payload.as_ref()) {
                                    let _ = shared.reads.owner.seen.lock().unwrap().insert(idx);
                                    read += 1;
                                }
                            }
                        }
                    }
                    channel.invite(shared.b_cid.load(Ordering::SeqCst)).await?;

                    read_until_final(
                        &mut channel,
                        a_cid,
                        &shared.reads.final_idx,
                        &shared.reads.owner,
                        "owner",
                    )
                    .await;
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_a = {
            let (me, o, sync, shared, a_cid_cell) = (
                a_name.clone(),
                o_name.clone(),
                sync.clone(),
                shared.clone(),
                a_cid_cell.clone(),
            );
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let reg = remote
                        .register_with_defaults(server_addr, &me, &me, PASSWORD)
                        .await?;
                    a_cid_cell.store(reg.cid, Ordering::SeqCst);
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &o).await?;
                    sync.wait().await;
                    sync.wait().await;

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let channel = next_group_channel(&mut events, "A").await;
                    sync.wait().await; // A's channel is open

                    let (tx, mut rx) = channel.split();
                    let drain = tokio::spawn(async move { while rx.next().await.is_some() {} });
                    let mut join_seen_at = None;
                    for idx in 0..SEND_CAP {
                        tx.send_message(SecBuffer::from(format!("a-{idx}").into_bytes()))
                            .await?;
                        if join_seen_at.is_none() && shared.b_joined.load(Ordering::SeqCst) {
                            join_seen_at = Some(idx + 1);
                            shared
                                .reads
                                .first_after_join
                                .store(idx + 1, Ordering::SeqCst);
                        }
                        let done = matches!(join_seen_at, Some(first) if idx + 1 >= first + SENT_AFTER_JOIN);
                        if done || idx + 1 == SEND_CAP {
                            shared.reads.final_idx.store(idx, Ordering::SeqCst);
                            break;
                        }
                        // Pacing so the stream is continuous but bounded; not part of any assertion.
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    sync.wait().await;
                    drain.abort();
                    drop(tx);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_b = {
            let (me, o, sync, shared, a_cid_cell) = (
                b_name.clone(),
                o_name.clone(),
                sync.clone(),
                shared.clone(),
                a_cid_cell.clone(),
            );
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let reg = remote
                        .register_with_defaults(server_addr, &me, &me, PASSWORD)
                        .await?;
                    shared.b_cid.store(reg.cid, Ordering::SeqCst);
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &o).await?;
                    sync.wait().await;
                    sync.wait().await; // A's channel is open

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "B").await;
                    shared.b_joined.store(true, Ordering::SeqCst);
                    let a_cid = a_cid_cell.load(Ordering::SeqCst);
                    read_until_final(
                        &mut channel,
                        a_cid,
                        &shared.reads.final_idx,
                        &shared.reads.b,
                        "B",
                    )
                    .await;
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_trio(
            server,
            DefaultNodeBuilder::default().build(owner).unwrap(),
            DefaultNodeBuilder::default().build(member_a).unwrap(),
            DefaultNodeBuilder::default().build(member_b).unwrap(),
        )
        .await;

        shared.reads.assert_nothing_lost(
            "",
            "messages from a member of the group were lost across B's join",
        );
    }
}
