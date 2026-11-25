#![cfg(not(target_family = "wasm"))]
//! A message sent again under its id is answered with the position it was first given, and
//! relayed once.
//!
//! ```text
//! O, M: register → connect → befriend; O creates a group inviting M; M joins
//! O: sends "once" under id X (answer: relayed, at p), sends it again under X
//!    (answer: AlreadyRelayed, at p), then sends "end"
//! M: reads until "end"; it must have read "once" exactly once, at p
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    fn answer_of(answer: GroupBroadcast) -> (Option<u64>, GroupDelivery) {
        match answer {
            GroupBroadcast::MessageResponse {
                position, delivery, ..
            } => (position.map(|p| p.seq), delivery),
            other => panic!("not a MessageResponse: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_sent_again_under_its_id_is_relayed_once() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("gro_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("grm_{}", &Uuid::new_v4().to_string()[..8]);
        let finished = Arc::new(Barrier::new(2));
        let first_at = Arc::new(Mutex::new(None));
        let read = Arc::new(Mutex::new(Vec::new()));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (finished, first_at) = (finished.clone(), first_at.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) = open_group(
                        &remote,
                        server_addr,
                        (&me, &peer),
                        MessageGroupOptions::default(),
                    )
                    .await?;
                    let id = GroupMessageId::random();
                    let once = || SecBuffer::from(b"once".to_vec());
                    channel.send_message_with_id(once(), id).await?;
                    let (first, delivery) = answer_of(next_send_answer(&mut channel).await);
                    assert!(delivery.is_complete(), "not relayed: {delivery:?}");
                    *first_at.lock().unwrap() = first;
                    channel.send_message_with_id(once(), id).await?;
                    let (again, delivery) = answer_of(next_send_answer(&mut channel).await);
                    assert_eq!(
                        delivery,
                        GroupDelivery::NotRelayed(NotRelayed::AlreadyRelayed)
                    );
                    assert_eq!(
                        again, first,
                        "the message sent again was given a new position"
                    );
                    channel
                        .send_message(SecBuffer::from(b"end".to_vec()))
                        .await?;
                    finished.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (finished, read) = (finished.clone(), read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    loop {
                        match channel.recv().await {
                            Some(GroupBroadcastPayload::Message {
                                payload, position, ..
                            }) => {
                                let text = String::from_utf8_lossy(payload.as_ref()).to_string();
                                read.lock().unwrap().push((text.clone(), position.seq));
                                if text == "end" {
                                    break;
                                }
                            }
                            Some(_) => {}
                            None => panic!("the member's group channel closed"),
                        }
                    }
                    finished.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let first = first_at
            .lock()
            .unwrap()
            .expect("the owner's message was not positioned");
        let read = read.lock().unwrap().clone();
        let once: Vec<u64> = read
            .iter()
            .filter(|(text, _)| text == "once")
            .map(|(_, seq)| *seq)
            .collect();
        assert_eq!(
            once,
            vec![first],
            "the member read the message {} time(s): {read:?}",
            once.len()
        );
    }
}
