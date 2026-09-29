#![cfg(not(target_family = "wasm"))]
//! A member's group messages are not lost when another member joins while it is sending.
//!
//! Every join is a CGKA epoch change. The owner advances to the new epoch the moment it
//! incorporates the joiner's KeyPackage, sends the Welcome to the joiner, and only then the
//! Commit to the existing members. A member that is sending in that window seals at the old
//! epoch; on arrival the owner (already on the new epoch) and the joiner cannot open it, and
//! the client handler drops it at TRACE as "not a permitted reader" — no `MessageDropped`, no
//! resend. `stress_test_group_broadcast` loses exactly one sender's message this way (#321).
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
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use futures::StreamExt;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use uuid::Uuid;

    /// How many of A's messages the owner reads before it invites B, so the join lands while A
    /// is already streaming at the settled epoch.
    const READ_BEFORE_INVITE: usize = 20;
    /// How many messages A sends after B's channel is open.
    const SENT_AFTER_JOIN: u64 = 200;
    /// Safety bound so a bug cannot make A send for ever.
    const SEND_CAP: u64 = 20_000;
    /// Safety bound for a reader waiting on the next message; exceeding it ends the read and the
    /// outcome assertion below reports what was missing. Not a latency assertion.
    const IDLE_BOUND: Duration = Duration::from_secs(30);
    const UNSET: u64 = u64::MAX;

    #[derive(Default)]
    struct Shared {
        b_cid: AtomicU64,
        b_joined: AtomicBool,
        first_after_join: AtomicU64,
        final_idx: AtomicU64,
        owner_seen: Mutex<BTreeSet<u64>>,
        owner_dropped: AtomicU64,
        b_seen: Mutex<BTreeSet<u64>>,
        b_dropped: AtomicU64,
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

    /// Read A's messages until A's final one arrives (or the idle bound passes), recording
    /// each index and every `MessageDropped`.
    async fn read_until_final(
        channel: &mut GroupChannel,
        a_cid: u64,
        shared: &Shared,
        seen: &Mutex<BTreeSet<u64>>,
        dropped: &AtomicU64,
        who: &str,
    ) {
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
                    let _ = dropped.fetch_add(1, Ordering::SeqCst);
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
        shared.first_after_join.store(UNSET, Ordering::SeqCst);
        shared.final_idx.store(UNSET, Ordering::SeqCst);
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
                                    let _ = shared.owner_seen.lock().unwrap().insert(idx);
                                    read += 1;
                                }
                            }
                        }
                    }
                    channel.invite(shared.b_cid.load(Ordering::SeqCst)).await?;

                    read_until_final(
                        &mut channel,
                        a_cid,
                        &shared,
                        &shared.owner_seen,
                        &shared.owner_dropped,
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
                            shared.first_after_join.store(idx + 1, Ordering::SeqCst);
                        }
                        let done = matches!(join_seen_at, Some(first) if idx + 1 >= first + SENT_AFTER_JOIN);
                        if done || idx + 1 == SEND_CAP {
                            shared.final_idx.store(idx, Ordering::SeqCst);
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
                        &shared,
                        &shared.b_seen,
                        &shared.b_dropped,
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
            "B's channel never opened while A was sending"
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
            "A sent a-0..=a-{final_idx}; B's channel opened before a-{first_after_join}. \
             Owner missing {} {:?} (MessageDropped seen: {}); \
             B missing {} of those sent after its join {:?} (MessageDropped seen: {})",
            owner_missing.len(),
            owner_missing,
            shared.owner_dropped.load(Ordering::SeqCst),
            b_missing.len(),
            b_missing,
            shared.b_dropped.load(Ordering::SeqCst),
        );
        log::warn!(target: "citadel", "{report}");
        assert!(
            owner_missing.is_empty() && b_missing.is_empty(),
            "messages from a member of the group were lost across B's join: {report}"
        );
    }
}
