#![cfg(not(target_family = "wasm"))]
//! A member that reconnects is back in its group, and reads it, while the group's owner is
//! offline.
//!
//! ```text
//! O befriends A and B; O creates a group with A and B; both join
//! O disconnects; everyone waits until the server holds no session for O
//! A disconnects and reconnects
//! B sends "without-owner-N" until A reads one; A must read one within the deadline
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::{befriend, run_trio};
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    struct Shared {
        sync: Barrier,
        owner_cid: AtomicU64,
        read: AtomicBool,
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

    async fn join(
        remote: &NodeRemote<StackedRatchet>,
        events: &mut Events,
        me: &str,
    ) -> Result<GroupChannel, NetworkError> {
        let invitation = next_invitation(events).await;
        let _ = responses::group_invite(invitation, true, remote).await?;
        Ok(next_group_channel(events, me).await)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_member_rejoins_and_reads_its_group_while_the_owner_is_away() {
        citadel_logging::setup_log();
        let (server, addr, server_remote) = probed_server();
        let tag = &Uuid::new_v4().to_string()[..8];
        let (o, a, b) = (
            format!("gwo_{tag}"),
            format!("gwa_{tag}"),
            format!("gwb_{tag}"),
        );
        let shared = Arc::new(Shared {
            sync: Barrier::new(3),
            owner_cid: AtomicU64::new(0),
            read: AtomicBool::new(false),
        });

        let owner = {
            let (me, a, b, shared) = (o.clone(), a.clone(), b.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (cid, conn) = register(&remote, addr, &me).await?;
                    shared.owner_cid.store(cid, Ordering::SeqCst);
                    shared.sync.wait().await;
                    befriend(&conn, cid, &me, &a).await?;
                    shared.sync.wait().await;
                    befriend(&conn, cid, &me, &b).await?;
                    shared.sync.wait().await;
                    let members = vec![a.clone().into(), b.clone().into()];
                    let channel = conn.create_group(Some(members)).await?;
                    shared.sync.wait().await; // both members joined
                    conn.disconnect().await?;
                    shared.sync.wait().await; // owner gone
                    shared.sync.wait().await; // test over
                    drop(channel);
                    remote.shutdown().await
                },
            )
        };

        let member_a = {
            let (me, o, shared) = (a.clone(), o.clone(), shared.clone());
            let server_remote = server_remote.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (cid, conn) = register(&remote, addr, &me).await?;
                    shared.sync.wait().await;
                    befriend(&conn, cid, &me, &o).await?;
                    shared.sync.wait().await;
                    shared.sync.wait().await;
                    let first = join(&remote, &mut events, &me).await?;
                    shared.sync.wait().await; // both members joined
                    let owner = shared.owner_cid.load(Ordering::SeqCst);
                    until_offline(server_of(&server_remote), owner).await;
                    shared.sync.wait().await; // owner gone
                    conn.disconnect().await?;
                    drop(first);
                    let conn = connect(&remote, &me).await?;
                    let read = tokio::time::timeout(REJOIN_DEADLINE, async {
                        let mut channel = next_group_channel(&mut events, "A").await;
                        next_message_with_prefix(&mut channel, "without-owner").await
                    })
                    .await;
                    shared.read.store(read.is_ok(), Ordering::SeqCst);
                    shared.sync.wait().await; // test over
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_b = {
            let (me, o, shared) = (b.clone(), o.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (cid, conn) = register(&remote, addr, &me).await?;
                    shared.sync.wait().await;
                    shared.sync.wait().await;
                    befriend(&conn, cid, &me, &o).await?;
                    shared.sync.wait().await;
                    let channel = join(&remote, &mut events, &me).await?;
                    shared.sync.wait().await; // both members joined
                    shared.sync.wait().await; // owner gone
                    let read = async {
                        while !shared.read.load(Ordering::SeqCst) {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    };
                    tokio::select! {
                        res = send_until(&channel, "without-owner", &shared.read) => res?,
                        _ = read => {}
                    }
                    shared.sync.wait().await; // test over
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_trio(
            server,
            client_node(owner),
            client_node(member_a),
            client_node(member_b),
        )
        .await;
        assert!(
            shared.read.load(Ordering::SeqCst),
            "a member that reconnected while the owner was away was not back in its group"
        );
    }
}
