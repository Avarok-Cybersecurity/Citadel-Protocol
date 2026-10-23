#![cfg(not(target_family = "wasm"))]
//! A group created with message limits has each message held to them by its server: one over the
//! size cap, or past its sender's rate, is refused, reaches nobody, and its sender is told why
//! with a typed `MessageRefused`.
//!
//! ```text
//! A, B: register → connect → befriend; A creates a group with limits inviting B; B joins
//! A sends each message in turn, reading the server's answer to each
//! A waits out the rate window and sends "end"; B records every message until "end"
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    const END: &[u8] = b"end";

    struct Outcome {
        /// The server's answer to each message, in order.
        answers: Vec<GroupBroadcast>,
        /// What the member received, in order, up to and including "end".
        received: Vec<Vec<u8>>,
    }

    async fn send_with_limits(limits: GroupMessageLimits, messages: Vec<Vec<u8>>) -> Outcome {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("lim_o_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("lim_m_{}", &Uuid::new_v4().to_string()[..8]);
        let answers = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(Barrier::new(2));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (answers, done) = (answers.clone(), done.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let options = MessageGroupOptions {
                        limits: Some(limits),
                        ..Default::default()
                    };
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), options).await?;
                    for message in messages {
                        channel.send_message(SecBuffer::from(message)).await?;
                        let answer = next_send_answer(&mut channel).await;
                        answers.lock().unwrap().push(answer);
                    }
                    // A fresh rate window, so "end" is admitted whatever came before it.
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                    channel.send_message(SecBuffer::from(END.to_vec())).await?;
                    let end = next_send_answer(&mut channel).await;
                    assert!(
                        matches!(end, GroupBroadcast::MessageResponse { success: true, .. }),
                        "{end:?}"
                    );
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (received, done) = (received.clone(), done.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    loop {
                        let payload = next_message_with_prefix(&mut channel, "").await;
                        let is_end = payload == END;
                        received.lock().unwrap().push(payload);
                        if is_end {
                            break;
                        }
                    }
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(owner)
            .unwrap();
        let member = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(member)
            .unwrap();
        run_pair(server, owner, member).await;
        let answers = std::mem::take(&mut *answers.lock().unwrap());
        let received = std::mem::take(&mut *received.lock().unwrap());
        Outcome { answers, received }
    }

    fn delivered(answer: &GroupBroadcast) -> bool {
        matches!(
            answer,
            GroupBroadcast::MessageResponse { success: true, .. }
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_over_the_groups_size_cap_is_refused_and_reaches_nobody() {
        let limits = GroupMessageLimits::new(1024, 16).unwrap();
        let large = vec![b'x'; 4096];
        let outcome = send_with_limits(limits, vec![b"small".to_vec(), large]).await;
        assert!(delivered(&outcome.answers[0]), "{:?}", outcome.answers);
        match &outcome.answers[1] {
            GroupBroadcast::MessageRefused {
                refusal: GroupMessageRefusal::TooLarge { bytes, max_bytes },
                ..
            } => {
                assert_eq!(*max_bytes, 1024);
                assert!(*bytes >= 4096, "the relayed ciphertext: {bytes}");
            }
            other => panic!("the large message was not refused for its size: {other:?}"),
        }
        assert_eq!(outcome.received, [b"small".to_vec(), END.to_vec()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_past_its_senders_rate_is_refused_and_reaches_nobody() {
        let limits = GroupMessageLimits::new(65536, 2).unwrap();
        let sends = ["r-1", "r-2", "r-3"]
            .map(|m| m.as_bytes().to_vec())
            .to_vec();
        let outcome = send_with_limits(limits, sends).await;
        assert!(delivered(&outcome.answers[0]) && delivered(&outcome.answers[1]));
        assert!(
            matches!(
                outcome.answers[2],
                GroupBroadcast::MessageRefused {
                    refusal: GroupMessageRefusal::RateLimited { max_per_second: 2 },
                    ..
                }
            ),
            "{:?}",
            outcome.answers
        );
        assert_eq!(
            outcome.received,
            [b"r-1".to_vec(), b"r-2".to_vec(), END.to_vec()]
        );
    }
}
