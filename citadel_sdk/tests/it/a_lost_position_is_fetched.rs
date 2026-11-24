#![cfg(not(target_family = "wasm"))]
//! A member of a replay group whose stream loses a position holds what follows, fetches the
//! gap from the server, and hands everything on in order. A member joining such a group can
//! read where it joined, and the others are told of its entry at a position before that.
//!
//! ```text
//! O, M: register → connect → befriend; O creates a replay group inviting M; M joins
//! O is told M entered, at a position; M's first position is after it
//! the server is set to lose the 2nd message it sends M; O sends "a", "b", "c"
//! M reads "a", "b", "c" in order, positions one after another, having fetched one gap
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_replay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::{gap_fetches, skip_group_message_to};
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_position_is_fetched_and_everything_is_handed_on_in_order() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = replay_server();
        let owner_name = format!("rgo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("rgm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let (joined, done) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let read = Arc::new(Mutex::new((Vec::new(), None, None)));
        let entered = Arc::new(AtomicU64::new(0));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (joined, done, member_cid) = (joined.clone(), done.clone(), member_cid.clone());
            let entered = entered.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), replay_options(LOG)).await?;
                    joined.wait().await;
                    entered.store(next_entry(&mut channel).await.seq, Ordering::SeqCst);
                    let _skip = skip_group_message_to(member_cid.load(Ordering::SeqCst), 2);
                    for text in ["a", "b", "c"] {
                        let _ = send_positioned(&mut channel, text.as_bytes().to_vec()).await;
                    }
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (joined, done, member_cid) = (joined.clone(), done.clone(), member_cid.clone());
            let read = read.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    joined.wait().await;
                    let got = read_until(&mut channel, "c").await;
                    *read.lock().unwrap() = (got, channel.order(), Some(channel.key()));
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let (read, order, key) = read.lock().unwrap().clone();
        assert_eq!(texts(&read), vec!["a", "b", "c"]);
        let at: Vec<u64> = read
            .iter()
            .filter_map(|r| match r {
                Read::Message { at, .. } => Some(at.seq),
                _ => None,
            })
            .collect();
        assert!(
            at.windows(2).all(|p| p[1] == p[0] + 1),
            "out of order: {at:?}"
        );
        assert_eq!(
            gap_fetches(key.expect("no key")),
            1,
            "the lost position was not fetched"
        );
        let joined_at = order
            .and_then(|o| o.joined)
            .expect("the joiner was not told where it joined");
        let entered = entered.load(Ordering::SeqCst);
        assert!(
            entered < joined_at && joined_at <= at[0],
            "entered at {entered}, joined at {joined_at}, read from {}",
            at[0]
        );
    }

    /// The position at which the owner is told a member entered the group.
    async fn next_entry(channel: &mut GroupChannel) -> GroupPosition {
        let entry = tokio::time::timeout(REJOIN_DEADLINE, async {
            loop {
                match channel.recv().await {
                    Some(GroupBroadcastPayload::Event {
                        payload:
                            GroupBroadcast::Ordered {
                                position, frame, ..
                            },
                    }) if matches!(
                        *frame,
                        GroupBroadcast::MemberStateChanged {
                            state: MemberState::EnteredGroup { .. },
                            ..
                        }
                    ) =>
                    {
                        return position
                    }
                    Some(other) => log::info!(target: "citadel", "[owner] {other:?}"),
                    None => panic!("the owner's channel closed"),
                }
            }
        });
        entry
            .await
            .expect("the owner was never told, at a position, that the member entered")
    }
}
