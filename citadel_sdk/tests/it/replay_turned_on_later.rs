#![cfg(not(target_family = "wasm"))]
//! An owner turns replay on for a group that had none: every member is told at a position,
//! numbering has no gaps from it, a full body of `MIN_REPLAY_BODY_BYTES` is carried, a larger
//! message than the group takes is refused, and each member can read the cap.
//!
//! ```text
//! O, M: register → connect → befriend; O creates an ordinary group inviting M; M joins
//! O sends "before"; O turns replay on; O sends a 16 384-byte body, one byte too many, "end"
//! M reads "before" (no chain head), replay turned on at s, the body at s+1, "end" at s+2
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_replay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_turned_on_later_is_positioned_and_carries_a_full_body() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = replay_server();
        let owner_name = format!("rlo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("rlm_{}", &Uuid::new_v4().to_string()[..8]);
        let done = Arc::new(Barrier::new(2));
        let refused = Arc::new(Mutex::new(None));
        let read = Arc::new(Mutex::new((Vec::new(), None)));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (done, refused) = (done.clone(), refused.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) = open_group(
                        &remote,
                        server_addr,
                        (&me, &peer),
                        MessageGroupOptions::default(),
                    )
                    .await?;
                    let _ = send_positioned(&mut channel, b"before".to_vec()).await;
                    channel.enable_replay(LOG).await?;
                    let body = vec![0xffu8; MIN_REPLAY_BODY_BYTES as usize];
                    let _ = send_positioned(&mut channel, body).await;
                    let over = vec![0u8; LOG.max_message_bytes as usize + 1];
                    channel.send_message(SecBuffer::from(over)).await?;
                    *refused.lock().unwrap() = Some(next_send_answer(&mut channel).await);
                    let _ = send_positioned(&mut channel, b"end".to_vec()).await;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (done, read) = (done.clone(), read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    let got = read_until(&mut channel, "end").await;
                    *read.lock().unwrap() = (got, channel.order());
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let (read, order) = read.lock().unwrap().clone();
        let body = format!("{MIN_REPLAY_BODY_BYTES} bytes");
        assert_eq!(texts(&read), vec!["before".to_string(), body, "end".into()]);
        let Read::Message { at: before, .. } = &read[0] else {
            panic!("'before' was not read first: {read:?}");
        };
        assert!(
            before.chain.is_none(),
            "a position before replay has no chain head"
        );
        let tail: Vec<&Read> = read
            .iter()
            .skip_while(
                |r| !matches!(r, Read::Event { event, .. } if event.contains("ReplayEnabled")),
            )
            .collect();
        let Some(Read::Event { at: since, .. }) = tail.first() else {
            panic!("the member was never told replay was on: {read:?}");
        };
        let after: Vec<u64> = tail
            .iter()
            .filter_map(|r| match r {
                Read::Message { at, .. } => Some(at.seq),
                _ => None,
            })
            .collect();
        assert_eq!(
            after,
            vec![since.seq + 1, since.seq + 2],
            "a gap after replay was turned on"
        );
        assert!(tail.iter().all(|r| match r {
            Read::Message { at, .. } | Read::Event { at, .. } => at.chain.is_some(),
            Read::Broken { .. } => false,
        }));
        let order = order.expect("the member cannot read the group's order");
        assert_eq!(order.since, since.seq);
        assert!(order.limits.max_message_bytes >= GroupLogLimits::MIN_MESSAGE_BYTES);
        assert!(matches!(
            refused.lock().unwrap().clone(),
            Some(GroupBroadcast::MessageRefused {
                refusal: GroupMessageRefusal::TooLarge { .. },
                ..
            })
        ));
    }
}
