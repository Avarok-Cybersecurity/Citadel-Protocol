#![cfg(not(target_family = "wasm"))]
//! When a group's owner leaves, the remaining member with the highest cid owns the group, every
//! member is told, and the group goes on: its members read each other, the new owner's control
//! requests are carried out, and the departed owner's are refused.
//!
//! ```text
//! O befriends A and B; O creates a group with A and B; both join
//! O leaves; A and B are each told the owner is now max(A, B) = S (the other is M)
//! O's kick is refused; O owns no group
//! M sends "after-owner-left"; S reads it
//! S kicks M; M is told it is out, and S owns the group
//! S sends "after-kick"; the server relays it to nobody, held or live: M is out
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::{befriend, run_trio};
    use crate::common::group_relay::*;
    use crate::common::group_succession::*;
    use citadel_io::tokio::sync::Barrier;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    struct Shared {
        sync: Barrier,
        cids: [AtomicU64; 2],
        owner_kick_refused: AtomicBool,
        successor_read: AtomicBool,
        kicked_member_told: AtomicBool,
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

    /// A member: joins, learns the successor, then plays the successor or the other member.
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
        let mut channel = next_group_channel(&mut events, &me).await;
        shared.sync.wait().await; // both joined

        let successor = shared.successor();
        let told = ownership_transferred(&mut channel).await;
        assert_eq!(told, successor, "[{me}] told of the wrong successor");
        assert_eq!(channel.owner(), Some(successor));
        shared.sync.wait().await; // ownership passed

        if cid == successor {
            let read = next_message_with_prefix(&mut channel, "after-owner-left").await;
            shared
                .successor_read
                .store(!read.is_empty(), Ordering::SeqCst);
        } else {
            channel
                .send_message(SecBuffer::from(b"after-owner-left".to_vec()))
                .await?;
        }
        shared.sync.wait().await; // read

        if cid == successor {
            let other = shared.cids[1 - slot].load(Ordering::SeqCst);
            channel.kick(other).await?;
            let kicked = next_on_channel(&mut channel, "KickResponse", |event| match event {
                GroupBroadcast::KickResponse { success, .. } => Some(*success),
                _ => None,
            })
            .await;
            assert!(kicked, "the new owner's kick was refused");
            assert_eq!(conn.list_owned_groups().await?, vec![channel.key()]);
            channel
                .send_message(SecBuffer::from(b"after-kick".to_vec()))
                .await?;
            let answer = next_send_answer(&mut channel).await;
            assert!(
                matches!(&answer, GroupBroadcast::MessageResponse {
                    delivery: GroupDelivery::Relayed { delivered, stored, not_delivered }, ..
                } if delivered.is_empty() && stored.is_empty() && not_delivered.is_empty()),
                "a message sent after a removal was relayed to the removed member: {answer:?}"
            );
        } else {
            let reason = disconnected(&mut channel).await;
            assert_eq!(reason, GroupEndReason::Removed);
            shared.kicked_member_told.store(true, Ordering::SeqCst);
        }
        shared.sync.wait().await; // test over
        drop(channel);
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_highest_cid_member_owns_the_group_once_its_owner_leaves() {
        citadel_logging::setup_log();
        let (server, addr, _server_remote) = probed_server();
        let tag = &Uuid::new_v4().to_string()[..8];
        let (o, a, b) = (
            format!("gso_{tag}"),
            format!("gsa_{tag}"),
            format!("gsb_{tag}"),
        );
        let shared = Arc::new(Shared {
            sync: Barrier::new(3),
            cids: [AtomicU64::new(0), AtomicU64::new(0)],
            owner_kick_refused: AtomicBool::new(false),
            successor_read: AtomicBool::new(false),
            kicked_member_told: AtomicBool::new(false),
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

                    assert!(leave(&mut channel).await?, "the owner's leave was refused");
                    let refused = matches!(
                        channel.kick(shared.successor()).await,
                        Err(err) if err.code == ErrorCode::PeerPermissionDenied
                    );
                    shared.owner_kick_refused.store(refused, Ordering::SeqCst);
                    assert_eq!(channel.owner(), None);
                    assert!(conn.list_owned_groups().await?.is_empty());
                    shared.sync.wait().await; // ownership passed
                    shared.sync.wait().await; // read
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
        assert!(
            shared.owner_kick_refused.load(Ordering::SeqCst),
            "the owner that left could still kick"
        );
        assert!(
            shared.successor_read.load(Ordering::SeqCst),
            "the new owner did not read a member's message"
        );
        assert!(
            shared.kicked_member_told.load(Ordering::SeqCst),
            "the member the new owner kicked was not told"
        );
    }
}
