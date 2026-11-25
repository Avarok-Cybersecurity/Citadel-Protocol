#![cfg(not(target_family = "wasm"))]
//! A join waits on at most a window of a busy member's messages, however many it has queued.
//!
//! The server handles a member's group broadcasts in the order they arrived, and the member's
//! acknowledgement of a Commit comes after every message it sealed before it; the joiner's
//! Welcome waits for that acknowledgement. A sender may have only `GROUP_SEND_WINDOW` messages
//! unanswered, so that is the most the acknowledgement can wait behind. The server's handling of
//! A is held, so the queue is built on every run rather than left to load:
//!
//! ```text
//! O creates a group with A; the server holds A's messages; A holds its Commits
//! A: sends WINDOW + EXTRA messages; the send past the window waits
//! O invites B; A applies the Commit and acknowledges it
//! the server's hold on A is released
//! the server must have relayed at most WINDOW of A's messages before A's acknowledgement,
//! and B's channel opens
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_epoch::{befriend, run_trio};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::{
        group_send_window_size, hold_group_relays, hold_inbound_commits,
        observe_commit_acknowledgements, observe_group_message_writes, observe_group_send_waits,
    };
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Messages A sends beyond the window.
    const EXTRA: usize = 8;

    #[derive(Default)]
    struct Shared {
        b_cid: AtomicU64,
        written_unanswered: AtomicUsize,
        relayed_before_ack: AtomicUsize,
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_join_waits_on_at_most_a_window_of_a_members_messages() {
        citadel_logging::setup_log();
        let window = group_send_window_size();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let tag = &Uuid::new_v4().to_string()[..8];
        let o_name = format!("gwo_{tag}");
        let a_name = format!("gwa_{tag}");
        let b_name = format!("gwb_{tag}");
        let sync = Arc::new(Barrier::new(3));
        let shared = Arc::new(Shared::default());

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
                    let reg = register(&remote, server_addr, &me).await?;
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &a).await?;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &b).await?;
                    sync.wait().await;

                    let channel = conn.create_group(Some(vec![a.clone().into()])).await?;
                    sync.wait().await; // A's channel is open
                    sync.wait().await; // A's queue is built
                    channel.invite(shared.b_cid.load(Ordering::SeqCst)).await?;
                    sync.wait().await; // B's channel is open
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
                    let reg = register(&remote, server_addr, &me).await?;
                    let a_cid = reg.cid;
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    befriend(&conn, a_cid, &me, &o).await?;
                    sync.wait().await;
                    sync.wait().await;

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let channel = next_group_channel(&mut events, "A").await;
                    let relays = hold_group_relays(a_cid);
                    let mut commits = hold_inbound_commits(a_cid);
                    let mut waits = observe_group_send_waits();
                    let mut writes = observe_group_message_writes();
                    let mut acks = observe_commit_acknowledgements();
                    sync.wait().await; // A's channel is open

                    let (tx, mut rx) = channel.split();
                    let drain = tokio::spawn(async move { while rx.next().await.is_some() {} });
                    let total = window + EXTRA;
                    let mut sender = tokio::spawn(async move {
                        for idx in 0..total {
                            tx.send_message(SecBuffer::from(format!("a-{idx}").into_bytes()))
                                .await?;
                        }
                        Ok::<_, NetworkError>(tx)
                    });
                    // The send past the window waits; without one, every send goes.
                    let mut sent = None;
                    let expected = tokio::select! {
                        _ = async { while waits.recv().await != Some(a_cid) {} } => window,
                        tx = &mut sender => { sent = Some(tx.unwrap()?); total }
                    };
                    for _ in 0..expected {
                        while writes.recv().await != Some(a_cid) {}
                    }
                    shared.written_unanswered.store(expected, Ordering::SeqCst);
                    sync.wait().await; // A's queue is built

                    commits.arrived().await;
                    commits.release().await;
                    drop(relays);
                    let ack = loop {
                        let ack = acks
                            .recv()
                            .await
                            .expect("the server handled A's acknowledgement");
                        if ack.member == a_cid {
                            break ack;
                        }
                    };
                    shared
                        .relayed_before_ack
                        .store(ack.relayed_before, Ordering::SeqCst);
                    let tx = match sent {
                        Some(tx) => tx,
                        None => sender.await.unwrap()?,
                    };
                    sync.wait().await; // B's channel is open
                    drain.abort();
                    drop(tx);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member_b = {
            let (me, o, sync, shared) =
                (b_name.clone(), o_name.clone(), sync.clone(), shared.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let reg = register(&remote, server_addr, &me).await?;
                    shared.b_cid.store(reg.cid, Ordering::SeqCst);
                    let conn = connect(&remote, &me).await?;
                    sync.wait().await;
                    sync.wait().await;
                    befriend(&conn, reg.cid, &me, &o).await?;
                    sync.wait().await;
                    sync.wait().await; // A's channel is open
                    sync.wait().await; // A's queue is built

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let channel = next_group_channel(&mut events, "B").await;
                    sync.wait().await; // B's channel is open
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_trio(server, node(owner), node(member_a), node(member_b)).await;

        let relayed = shared.relayed_before_ack.load(Ordering::SeqCst);
        assert!(
            relayed <= window,
            "A's acknowledgement waited behind {relayed} of its messages, more than the window of {window}"
        );
        assert_eq!(
            shared.written_unanswered.load(Ordering::SeqCst),
            window,
            "A wrote more messages than the window holds with none answered"
        );
    }

    async fn register(
        remote: &NodeRemote<StackedRatchet>,
        server_addr: std::net::SocketAddr,
        me: &str,
    ) -> Result<RegisterSuccess, NetworkError> {
        remote
            .register_with_defaults(
                server_addr,
                me,
                me,
                PASSWORD,
                CertVerification::SelfSignedAccepted,
            )
            .await
    }

    fn node<K: NetKernel<StackedRatchet> + 'static>(kernel: K) -> NodeFuture<'static, K> {
        citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(kernel)
            .unwrap()
    }
}
