#![cfg(not(target_family = "wasm"))]
//! A joiner reads every message a member sends after the joiner's channel opens, even when that
//! member is slow to apply the joiner's Commit. Until it does, the member seals at the epoch
//! before the join, which the joiner can never read, so the joiner's Welcome must wait for it.
//! A's Commit is held at A's packet processor, so the slow member is not left to chance:
//!
//! ```text
//! O creates a group with A; A holds every Commit it receives; O invites B
//! A: the Commit for B's join arrives and is held
//! A: waits until B's channel opens, or the server reports it is waiting on A
//! A: seals BURST messages at the old epoch; the server relays every one of them
//! A: releases the Commit and applies it; waits for B's channel; sends AFTER_JOIN more
//! B must read every message A sent after B's channel opened
//! ```
//!
//! A Welcome sent at once opens B's channel before the burst, and B can read none of it.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::{watch, Barrier};
    use citadel_proto::test_hooks::{hold_inbound_commits, observe_commit_gates};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// Messages A seals at the old epoch while its Commit is held.
    const BURST: u64 = 20;
    /// Messages A sends once B's channel is open and its Commit is applied.
    const AFTER_JOIN: u64 = 50;

    struct Shared {
        a_cid: AtomicU64,
        b_cid: AtomicU64,
        b_open: watch::Sender<bool>,
        reads: Reads,
        a_waited_for: Mutex<&'static str>,
    }

    /// Send `a-idx`, noting the first index sent once B's channel is open.
    async fn send_indexed(
        channel: &GroupChannel,
        shared: &Shared,
        idx: u64,
    ) -> Result<(), NetworkError> {
        if *shared.b_open.borrow() {
            let _ = shared.reads.first_after_join.compare_exchange(
                UNSET,
                idx,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        channel
            .send_message(SecBuffer::from(format!("a-{idx}").into_bytes()))
            .await
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_joiner_reads_everything_a_slow_member_sends_after_its_channel_opens() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let tag = &Uuid::new_v4().to_string()[..8];
        let o_name = format!("jho_{tag}");
        let a_name = format!("jha_{tag}");
        let b_name = format!("jhb_{tag}");
        let sync = Arc::new(Barrier::new(3));
        let (b_open, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            a_cid: AtomicU64::new(UNSET),
            b_cid: AtomicU64::new(UNSET),
            b_open,
            reads: Reads::default(),
            a_waited_for: Mutex::new("nothing"),
        });

        let owner = {
            let (me, a, b, sync, shared) = (
                o_name.clone(),
                a_name.clone(),
                b_name.clone(),
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
                    befriend(&conn, reg.cid, &me, &b).await?;
                    sync.wait().await;

                    let mut channel = conn.create_group(Some(vec![a.clone().into()])).await?;
                    sync.wait().await; // A's channel is open and A holds its Commits
                    channel.invite(shared.b_cid.load(Ordering::SeqCst)).await?;
                    read_until_final(
                        &mut channel,
                        shared.a_cid.load(Ordering::SeqCst),
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
            let (me, o, sync, shared) =
                (a_name.clone(), o_name.clone(), sync.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let reg = remote
                        .register_with_defaults(server_addr, &me, &me, PASSWORD)
                        .await?;
                    shared.a_cid.store(reg.cid, Ordering::SeqCst);
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &o).await?;
                    sync.wait().await;
                    sync.wait().await;

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "A").await;
                    let key = channel.key();
                    let mut hold = hold_inbound_commits(reg.cid);
                    let mut gates = observe_commit_gates();
                    sync.wait().await; // A's channel is open and A holds its Commits

                    hold.arrived().await;
                    let mut b_open = shared.b_open.subscribe();
                    let waited_for = tokio::select! {
                        _ = b_open.wait_for(|open| *open) => "B's channel to open",
                        _ = async {
                            while let Some(gate) = gates.recv().await {
                                if gate.key == key && gate.awaiting.contains(&reg.cid) {
                                    return;
                                }
                            }
                            std::future::pending::<()>().await
                        } => "the server to report it waits on A",
                    };
                    *shared.a_waited_for.lock().unwrap() = waited_for;

                    for idx in 0..BURST {
                        send_indexed(&channel, &shared, idx).await?;
                    }
                    relayed(&mut channel, BURST).await;
                    hold.release().await;

                    let _ = b_open.wait_for(|open| *open).await;
                    for idx in BURST..BURST + AFTER_JOIN {
                        send_indexed(&channel, &shared, idx).await?;
                    }
                    let last = BURST + AFTER_JOIN - 1;
                    shared.reads.final_idx.store(last, Ordering::SeqCst);
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_b = {
            let (me, o, sync, shared) =
                (b_name.clone(), o_name.clone(), sync.clone(), shared.clone());
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
                    sync.wait().await; // A's channel is open and A holds its Commits

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "B").await;
                    let _ = shared.b_open.send(true);
                    read_until_final(
                        &mut channel,
                        shared.a_cid.load(Ordering::SeqCst),
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

        let context = format!(
            "A held its Commit and waited for {}; a-0..a-{BURST} were sealed at the old epoch. ",
            shared.a_waited_for.lock().unwrap()
        );
        shared.reads.assert_nothing_lost(
            &context,
            "a joiner lost messages a member sent after its channel opened",
        );
    }
}
