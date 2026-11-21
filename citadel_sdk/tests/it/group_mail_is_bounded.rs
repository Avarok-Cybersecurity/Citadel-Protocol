#![cfg(not(target_family = "wasm"))]
//! What a server holds for an offline member of a group is bounded, and a message beyond the
//! bound is reported to its sender rather than stored.
//!
//! ```text
//! A, B: register → connect → befriend; A creates an ordinary group inviting B; B joins
//! B disconnects; A waits until the server holds no session for B
//! A sends CAP + OVER messages, one at a time, reading each answer
//! the server holds at most CAP of them for B, and OVER answers report a message not stored
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// The most messages the server holds for one member of one group.
    const CAP: usize = 8;
    /// Messages sent beyond it.
    const OVER: usize = 3;

    #[tokio::test(flavor = "multi_thread")]
    async fn mail_for_an_offline_member_is_capped_and_the_sender_is_told() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = probed_server();
        let owner_name = format!("gbo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gbm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let member_away = Arc::new(Barrier::new(2));
        let held = Arc::new(AtomicUsize::new(usize::MAX));
        let not_stored = Arc::new(AtomicUsize::new(0));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (member_cid, member_away) = (member_cid.clone(), member_away.clone());
            let (held, not_stored) = (held.clone(), not_stored.clone());
            let server_remote = server_remote.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) = open_group(
                        &remote,
                        server_addr,
                        (&me, &peer),
                        MessageGroupOptions::default(),
                    )
                    .await?;
                    member_away.wait().await;
                    let server = server_of(&server_remote);
                    let member = member_cid.load(Ordering::SeqCst);
                    until_offline(server, member).await;
                    for n in 0..CAP + OVER {
                        channel
                            .send_message(SecBuffer::from(format!("m-{n}").into_bytes()))
                            .await?;
                        let answer = next_send_answer(&mut channel).await;
                        if !matches!(
                            answer,
                            GroupBroadcast::MessageResponse { success: true, .. }
                        ) {
                            let _ = not_stored.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let count = mailed_group_messages(server, member, channel.key()).await;
                    held.store(count, Ordering::SeqCst);
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (member_cid, member_away) = (member_cid.clone(), member_away.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    conn.disconnect().await?;
                    member_away.wait().await;
                    drop(channel);
                    remote.shutdown().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let held = held.load(Ordering::SeqCst);
        assert!(
            held <= CAP,
            "the server held {held} messages for one member"
        );
        assert_eq!(
            not_stored.load(Ordering::SeqCst),
            OVER,
            "each message beyond the cap must be reported to its sender"
        );
    }
}
