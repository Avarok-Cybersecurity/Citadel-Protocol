#![cfg(not(target_family = "wasm"))]
//! A member's group messages reach the other members in the order it sent them, even when the
//! server takes longer over some of them than over the ones sent after.
//!
//! ```text
//! O, M: register → connect → befriend; O creates a group inviting M; M joins
//! the server takes 30 ms longer over every 4th message from M
//! M: sends "m-0" .. "m-39" back to back
//! O must read m-0 .. m-39, in that order
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::slow_group_messages_from;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    const SENT: u64 = 40;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_members_group_messages_arrive_in_the_order_sent() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("goo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gom_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let read_all = Arc::new(Barrier::new(2));
        let read = Arc::new(Mutex::new(Vec::new()));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (member_cid, read_all, read) = (member_cid.clone(), read_all.clone(), read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) = open_group(
                        &remote,
                        server_addr,
                        (&me, &peer),
                        MessageGroupOptions::default(),
                    )
                    .await?;
                    while (read.lock().unwrap().len() as u64) < SENT {
                        match channel.recv().await {
                            Some(GroupBroadcastPayload::Message { payload, sender, .. })
                                if sender == member_cid.load(Ordering::SeqCst) =>
                            {
                                let text = String::from_utf8_lossy(payload.as_ref()).to_string();
                                read.lock().unwrap().push(text);
                            }
                            Some(_) => {}
                            None => panic!("the owner's group channel closed"),
                        }
                    }
                    read_all.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (member_cid, read_all) = (member_cid.clone(), read_all.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    let _slow = slow_group_messages_from(conn.cid, 4, Duration::from_millis(30));
                    for idx in 0..SENT {
                        channel
                            .send_message(SecBuffer::from(format!("m-{idx}").into_bytes()))
                            .await?;
                    }
                    read_all.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let expected = (0..SENT).map(|idx| format!("m-{idx}")).collect::<Vec<_>>();
        assert_eq!(
            *read.lock().unwrap(),
            expected,
            "the owner did not read the member's messages in the order it sent them"
        );
    }
}
