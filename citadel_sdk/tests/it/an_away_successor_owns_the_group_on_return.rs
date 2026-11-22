#![cfg(not(target_family = "wasm"))]
//! When a group's owner leaves while the member that succeeds it (the highest cid) is offline,
//! ownership is recorded for that member and the group goes on relaying. On its return the
//! member owns the group from the state it kept: it reads everything sent while it was away,
//! and the members read what it sends as the owner.
//!
//! ```text
//! O befriends A and B; O creates a group with A and B; both join
//! S = max(A, B) goes offline; M is the other
//! O leaves; M is told S owns the group
//! M sends "away-0..3"; the server holds all four for S
//! S reconnects; its group is restored from this device, not re-founded, and it commits
//! S reads away-0..3 in order, owns the group, and M reads "from-the-new-owner"
//! S removes M, and M is told it was removed
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::{befriend, run_trio};
    use crate::common::group_relay::*;
    use crate::common::group_succession::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::observe_commit_gates;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    const AWAY: usize = 4;

    struct Shared {
        sync: Barrier,
        cids: [AtomicU64; 2],
        server: ServerRemote,
        successor_read_all: AtomicBool,
        member_read_owner: AtomicBool,
        member_removed: AtomicBool,
    }

    impl Shared {
        fn successor(&self) -> u64 {
            self.cids[0]
                .load(Ordering::SeqCst)
                .max(self.cids[1].load(Ordering::SeqCst))
        }
    }

    async fn register(
        remote: &NodeRemote<StackedRatchet>,
        addr: std::net::SocketAddr,
        me: &str,
    ) -> Result<(u64, CitadelClientServerConnection<StackedRatchet>), NetworkError> {
        let reg = remote
            .register_with_defaults(addr, me, me, PASSWORD, CertVerification::SelfSignedAccepted)
            .await?;
        Ok((reg.cid, connect(remote, me).await?))
    }

    async fn successor(
        remote: &NodeRemote<StackedRatchet>,
        events: &mut Events,
        (me, cid): (&str, u64),
        conn: CitadelClientServerConnection<StackedRatchet>,
        channel: GroupChannel,
        shared: &Shared,
    ) -> Result<(), NetworkError> {
        let key = channel.key();
        drop(channel);
        conn.disconnect().await?;
        until_offline(server_of(&shared.server), cid).await;
        shared.sync.wait().await; // away
        shared.sync.wait().await; // owner left
        shared.sync.wait().await; // held

        let mut gates = observe_commit_gates();
        let conn = connect(remote, me).await?;
        let mut channel = next_group_channel(events, me).await;
        // What was held is replayed first, and the restore is reported after it.
        let (read, source) = held_then_restored(&mut channel).await;
        assert_eq!(
            source,
            GroupStateSource::ThisDevice,
            "the successor's group was not resumed from the state it kept"
        );
        let expected: Vec<Vec<u8>> = (0..AWAY)
            .map(|n| format!("away-{n}").into_bytes())
            .collect();
        assert_eq!(
            read, expected,
            "the successor lost or reordered what was held for it"
        );
        shared.successor_read_all.store(true, Ordering::SeqCst);
        let other =
            shared.cids[0].load(Ordering::SeqCst) ^ shared.cids[1].load(Ordering::SeqCst) ^ cid;
        // Its first act as the owner is a Commit that cuts out the owner that left.
        let committed = tokio::time::timeout(REJOIN_DEADLINE, async {
            while let Some(gate) = gates.recv().await {
                if gate.key == key && gate.awaiting == [other] {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);
        assert!(
            committed,
            "the successor did not commit as the owner on its return"
        );
        assert_eq!(conn.list_owned_groups().await?, vec![key]);
        assert_eq!(channel.owner(), Some(cid));
        send_until(&channel, "from-the-new-owner", &shared.member_read_owner).await?;
        // It acts as the owner: its removal of the other member is carried out.
        channel.kick(other).await?;
        let kicked = next_on_channel(&mut channel, "KickResponse", |event| match event {
            GroupBroadcast::KickResponse { success, .. } => Some(*success),
            _ => None,
        })
        .await;
        assert!(kicked, "the new owner's kick was refused");
        shared.sync.wait().await; // test over
        drop(channel);
        conn.shutdown_kernel().await
    }

    async fn held_then_restored(channel: &mut GroupChannel) -> (Vec<Vec<u8>>, GroupStateSource) {
        tokio::time::timeout(REJOIN_DEADLINE, async {
            let mut read = Vec::with_capacity(AWAY);
            loop {
                match channel.recv().await {
                    Some(GroupBroadcastPayload::Message { payload, .. }) => {
                        read.push(payload.as_ref().to_vec())
                    }
                    Some(GroupBroadcastPayload::Event {
                        payload: GroupBroadcast::Restored { source, .. },
                    }) => return (read, source),
                    Some(other) => {
                        log::info!(target: "citadel", "while waiting for the restore: {other:?}")
                    }
                    None => panic!("the restored channel closed before the restore was reported"),
                }
            }
        })
        .await
        .expect("the successor was not told its group was restored")
    }

    async fn other_member(
        conn: CitadelClientServerConnection<StackedRatchet>,
        mut channel: GroupChannel,
        shared: &Shared,
    ) -> Result<(), NetworkError> {
        let successor = shared.successor();
        shared.sync.wait().await; // away
        assert_eq!(ownership_transferred(&mut channel).await, successor);
        shared.sync.wait().await; // owner left
        for n in 0..AWAY {
            channel
                .send_message(SecBuffer::from(format!("away-{n}").into_bytes()))
                .await?;
            let answer = next_send_answer(&mut channel).await;
            assert!(
                matches!(&answer, GroupBroadcast::MessageResponse {
                    delivery: GroupDelivery::Relayed { stored, .. }, ..
                } if stored.contains(&successor)),
                "a message sent while the successor was away was not held for it: {answer:?}"
            );
        }
        let held = mailed_group_messages(server_of(&shared.server), successor, channel.key()).await;
        assert_eq!(
            held, AWAY,
            "the server did not hold every message for the successor"
        );
        shared.sync.wait().await; // held
        let _ = next_message_with_prefix(&mut channel, "from-the-new-owner").await;
        shared.member_read_owner.store(true, Ordering::SeqCst);
        assert_eq!(disconnected(&mut channel).await, GroupEndReason::Removed);
        shared.member_removed.store(true, Ordering::SeqCst);
        shared.sync.wait().await; // test over
        drop(channel);
        conn.shutdown_kernel().await
    }

    async fn member(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        (me, owner, slot): (String, String, usize),
        shared: Arc<Shared>,
    ) -> Result<(), NetworkError> {
        let (cid, conn) = register(&remote, addr, &me).await?;
        shared.cids[slot].store(cid, Ordering::SeqCst);
        shared.sync.wait().await; // registered
        for turn in 0..2 {
            if turn == slot {
                befriend(&conn, cid, &me, &owner).await?;
            }
            shared.sync.wait().await;
        }
        let invitation = next_invitation(&mut events).await;
        let _ = responses::group_invite(invitation, true, &remote).await?;
        let channel = next_group_channel(&mut events, &me).await;
        shared.sync.wait().await; // both joined
        if cid == shared.successor() {
            successor(&remote, &mut events, (&me, cid), conn, channel, &shared).await
        } else {
            other_member(conn, channel, &shared).await
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_away_successor_owns_the_group_on_return_with_nothing_lost() {
        citadel_logging::setup_log();
        let (server, addr, server_remote) = probed_server();
        let tag = &Uuid::new_v4().to_string()[..8];
        let (o, a, b) = (
            format!("aso_{tag}"),
            format!("asa_{tag}"),
            format!("asb_{tag}"),
        );
        let shared = Arc::new(Shared {
            sync: Barrier::new(3),
            cids: [AtomicU64::new(0), AtomicU64::new(0)],
            server: server_remote,
            successor_read_all: AtomicBool::new(false),
            member_read_owner: AtomicBool::new(false),
            member_removed: AtomicBool::new(false),
        });

        let owner = {
            let (me, a, b, shared) = (o.clone(), a.clone(), b.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (cid, conn) = register(&remote, addr, &me).await?;
                    shared.sync.wait().await; // registered
                    befriend(&conn, cid, &me, &a).await?;
                    shared.sync.wait().await;
                    befriend(&conn, cid, &me, &b).await?;
                    shared.sync.wait().await;
                    let members = vec![a.clone().into(), b.clone().into()];
                    let mut channel = conn.create_group(Some(members)).await?;
                    shared.sync.wait().await; // both joined
                    shared.sync.wait().await; // away
                    assert!(leave(&mut channel).await?, "the owner's leave was refused");
                    shared.sync.wait().await; // owner left
                    shared.sync.wait().await; // held
                    shared.sync.wait().await; // test over
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_node = |me: &str, slot| {
            let (me, o, shared) = (me.to_string(), o.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, events: Events| async move {
                    member(remote, events, addr, (me, o, slot), shared).await
                },
            )
        };

        run_trio(
            server,
            client_node(owner),
            client_node(member_node(&a, 0)),
            client_node(member_node(&b, 1)),
        )
        .await;
        assert!(shared.successor_read_all.load(Ordering::SeqCst));
        assert!(shared.member_read_owner.load(Ordering::SeqCst));
        assert!(shared.member_removed.load(Ordering::SeqCst));
    }
}
