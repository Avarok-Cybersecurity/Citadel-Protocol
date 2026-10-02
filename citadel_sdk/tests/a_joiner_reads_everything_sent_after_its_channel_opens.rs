#![cfg(not(target_family = "wasm"))]
//! A joiner reads every message a member sends after the joiner's channel opens, even when that
//! member is slow to apply the joiner's Commit.
//!
//! A member seals at the epoch it holds. Until it applies the owner's Commit for a join, that is
//! the epoch before the join, which the joiner can never read (join forward secrecy). So the
//! owner must not let the joiner's channel open while any member could still seal at that
//! epoch. This test holds A's Commit at A's packet processor, so the slow member is not left to
//! chance:
//!
//! ```text
//! O creates a group with A; A holds every Commit it receives
//! O invites B → B accepts → O adds B (Commit to A, Welcome for B)
//! A: the Commit arrives and is held
//! A: waits until B's channel opens, or the server reports it is waiting on A
//! A: sends BURST messages, sealed at the old epoch; the server relays every one of them
//! A: releases the Commit and applies it; waits for B's channel; sends AFTER_JOIN more
//! B must read every message A sent after B's channel opened
//! ```
//!
//! When the Welcome is not held back, B's channel is already open when A seals the burst, and B
//! cannot read any of it.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::{watch, Barrier};
    use citadel_proto::test_hooks::{hold_inbound_commits, observe_commit_gates};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use uuid::Uuid;

    /// Messages A seals at the old epoch while its Commit is held.
    const BURST: u64 = 20;
    /// Messages A sends once B's channel is open and its Commit is applied.
    const AFTER_JOIN: u64 = 50;
    /// Safety bound for a reader waiting on the next message; exceeding it ends the read and the
    /// outcome assertion reports what was missing. Not a latency assertion.
    const IDLE_BOUND: Duration = Duration::from_secs(30);
    const UNSET: u64 = u64::MAX;

    struct Shared {
        a_cid: AtomicU64,
        b_cid: AtomicU64,
        b_open: watch::Sender<bool>,
        first_after_join: AtomicU64,
        final_idx: AtomicU64,
        owner_seen: Mutex<BTreeSet<u64>>,
        b_seen: Mutex<BTreeSet<u64>>,
        b_dropped: AtomicU64,
        a_waited_for: Mutex<&'static str>,
    }

    fn parse_idx(payload: &[u8]) -> Option<u64> {
        std::str::from_utf8(payload)
            .ok()?
            .strip_prefix("a-")?
            .parse()
            .ok()
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

    /// Read A's messages until A's final one arrives (or the idle bound passes).
    async fn read_until_final(
        channel: &mut GroupChannel,
        shared: &Shared,
        seen: &Mutex<BTreeSet<u64>>,
        dropped: Option<&AtomicU64>,
        who: &str,
    ) {
        let a_cid = shared.a_cid.load(Ordering::SeqCst);
        loop {
            let final_idx = shared.final_idx.load(Ordering::SeqCst);
            if final_idx != UNSET && seen.lock().unwrap().contains(&final_idx) {
                return;
            }
            match tokio::time::timeout(IDLE_BOUND, channel.recv()).await {
                Ok(Some(GroupBroadcastPayload::Message { payload, sender })) if sender == a_cid => {
                    if let Some(idx) = parse_idx(payload.as_ref()) {
                        let _ = seen.lock().unwrap().insert(idx);
                    }
                }
                Ok(Some(GroupBroadcastPayload::Event {
                    payload: GroupBroadcast::MessageDropped { .. },
                })) => {
                    if let Some(dropped) = dropped {
                        let _ = dropped.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    log::warn!(target: "citadel", "[{who}] group channel closed");
                    return;
                }
                Err(_) => {
                    log::warn!(target: "citadel", "[{who}] no message for {IDLE_BOUND:?}; ending the read");
                    return;
                }
            }
        }
    }

    /// Send `a-idx`, noting the first index sent once B's channel is open.
    async fn send_indexed(
        channel: &GroupChannel,
        shared: &Shared,
        idx: u64,
    ) -> Result<(), NetworkError> {
        if *shared.b_open.borrow() {
            let _ = shared.first_after_join.compare_exchange(
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

    /// Wait for the server's acknowledgement of each of A's next `count` messages: a message
    /// the server has acknowledged has been relayed to every member, B included.
    async fn relayed(channel: &mut GroupChannel, count: u64) {
        let mut acknowledged = 0;
        while acknowledged < count {
            match channel.recv().await {
                Some(GroupBroadcastPayload::Event {
                    payload: GroupBroadcast::MessageResponse { success, .. },
                }) => {
                    assert!(success, "the server could not relay one of A's messages");
                    acknowledged += 1;
                }
                Some(_) => {}
                None => panic!("A's group channel closed"),
            }
        }
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
            first_after_join: AtomicU64::new(UNSET),
            final_idx: AtomicU64::new(UNSET),
            owner_seen: Mutex::new(BTreeSet::new()),
            b_seen: Mutex::new(BTreeSet::new()),
            b_dropped: AtomicU64::new(0),
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
                    read_until_final(&mut channel, &shared, &shared.owner_seen, None, "owner")
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
                    shared
                        .final_idx
                        .store(BURST + AFTER_JOIN - 1, Ordering::SeqCst);
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
                        &shared,
                        &shared.b_seen,
                        Some(&shared.b_dropped),
                        "B",
                    )
                    .await;
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member_a = DefaultNodeBuilder::default().build(member_a).unwrap();
        let member_b = DefaultNodeBuilder::default().build(member_b).unwrap();
        let clients = async move { futures::future::try_join3(owner, member_a, member_b).await };
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

        let final_idx = shared.final_idx.load(Ordering::SeqCst);
        let first_after_join = shared.first_after_join.load(Ordering::SeqCst);
        assert_ne!(final_idx, UNSET, "A never finished sending");
        assert_ne!(
            first_after_join, UNSET,
            "A sent nothing after B's channel opened"
        );
        let owner_missing: Vec<u64> = {
            let seen = shared.owner_seen.lock().unwrap();
            (0..=final_idx).filter(|i| !seen.contains(i)).collect()
        };
        let b_missing: Vec<u64> = {
            let seen = shared.b_seen.lock().unwrap();
            (first_after_join..=final_idx)
                .filter(|i| !seen.contains(i))
                .collect()
        };
        let report = format!(
            "A held its Commit and waited for {}; A sent a-0..=a-{final_idx}, a-0..a-{BURST} at the \
             old epoch; B's channel opened before a-{first_after_join}. Owner missing {owner_missing:?}; \
             B missing {} of those sent after its channel opened {b_missing:?} (MessageDropped seen: {})",
            shared.a_waited_for.lock().unwrap(),
            b_missing.len(),
            shared.b_dropped.load(Ordering::SeqCst),
        );
        log::warn!(target: "citadel", "{report}");
        assert!(
            owner_missing.is_empty() && b_missing.is_empty(),
            "a joiner lost messages a member sent after its channel opened: {report}"
        );
    }
}
