#![cfg(not(target_family = "wasm"))]
//! The server's answer to a group message says which members it reached. A message to an
//! ephemeral group whose only other member is offline reaches nobody, so the answer does not
//! report it delivered.
//!
//! ```text
//! A, B: register → connect → befriend; A creates an ephemeral group inviting B; B joins
//! B disconnects; A waits until the server holds no session for B
//! A sends "while-away"; the answer must not report it delivered
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_no_member_received_is_not_reported_delivered() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = probed_server();
        let owner_name = format!("gso_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gsm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let member_away = Arc::new(Barrier::new(2));
        let answer = Arc::new(Mutex::new(None));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (member_cid, member_away, answer) =
                (member_cid.clone(), member_away.clone(), answer.clone());
            let server_remote = server_remote.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let options = MessageGroupOptions {
                        ephemeral: true,
                        ..Default::default()
                    };
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), options).await?;
                    member_away.wait().await;
                    let server = server_of(&server_remote);
                    until_offline(server, member_cid.load(Ordering::SeqCst)).await;
                    channel
                        .send_message(SecBuffer::from(b"while-away".to_vec()))
                        .await?;
                    *answer.lock().unwrap() = Some(next_send_answer(&mut channel).await);
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
        let answer = answer
            .lock()
            .unwrap()
            .take()
            .expect("the send was answered");
        assert!(
            !matches!(&answer, GroupBroadcast::MessageResponse { delivery, .. } if delivery.is_complete()),
            "a message that reached no member was reported delivered: {answer:?}"
        );
    }
}
