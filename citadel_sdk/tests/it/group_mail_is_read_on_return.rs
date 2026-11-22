#![cfg(not(target_family = "wasm"))]
//! A member of an ordinary group that was offline while a message was sent reads that message
//! when it comes back. The server holds it for the member, and the member's returning session
//! opens it.
//!
//! ```text
//! A, B: register → connect → befriend; A creates an ordinary group inviting B; B joins
//! B disconnects; A waits until the server holds no session for B
//! A sends "while-away" and gets the server's answer
//! B reconnects; its group channel must yield "while-away" within the deadline
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_mailed_while_a_member_was_offline_is_read_when_it_returns() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = probed_server();
        let owner_name = format!("gmo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gmm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let member_away = Arc::new(Barrier::new(2));
        let mailed = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let read = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (member_cid, member_away, mailed, done) = (
                member_cid.clone(),
                member_away.clone(),
                mailed.clone(),
                done.clone(),
            );
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
                    until_offline(server, member_cid.load(Ordering::SeqCst)).await;
                    channel
                        .send_message(SecBuffer::from(b"while-away".to_vec()))
                        .await?;
                    let answer = next_send_answer(&mut channel).await;
                    log::info!(target: "citadel", "[owner] send answer: {answer:?}");
                    mailed.wait().await;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (member_cid, member_away, mailed, done) = (
                member_cid.clone(),
                member_away.clone(),
                mailed.clone(),
                done.clone(),
            );
            let read = read.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, first) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    conn.disconnect().await?;
                    member_away.wait().await;
                    mailed.wait().await;
                    let conn = connect(&remote, &me).await?;
                    drop(first);
                    let got = tokio::time::timeout(REJOIN_DEADLINE, async {
                        let mut channel = next_group_channel(&mut events, "member").await;
                        next_message_with_prefix(&mut channel, "while-away").await
                    })
                    .await;
                    read.store(got.is_ok(), Ordering::SeqCst);
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        assert!(
            read.load(Ordering::SeqCst),
            "the member did not read the message sent while it was offline"
        );
    }
}
