#![cfg(not(target_family = "wasm"))]
//! A member back in a replay group after more was sent than the log keeps is told which
//! positions it lost, and is then replayed what the log still has, in order.
//!
//! ```text
//! O, M: register → connect → befriend; O creates a replay group keeping 3 entries, inviting M
//! O sends "first"; M reads it, then disconnects; O sends "0".."5" while M is away
//! M reconnects: it is told the positions after "first" up to "3" are gone, then reads "3".."5"
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_replay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn positions_older_than_the_log_keeps_are_named_before_the_rest_is_replayed() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = replay_server();
        let owner_name = format!("rko_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("rkm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let (read_first, away, sent, done) = (
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
        );
        let first_at = Arc::new(AtomicU64::new(0));
        let three_at = Arc::new(AtomicU64::new(0));
        let read = Arc::new(Mutex::new(Vec::new()));
        let small = GroupLogLimits {
            max_messages: 3,
            ..LOG
        };

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (read_first, away, sent, done) =
                (read_first.clone(), away.clone(), sent.clone(), done.clone());
            let (member_cid, server_remote) = (member_cid.clone(), server_remote.clone());
            let (first_at, three_at) = (first_at.clone(), three_at.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), replay_options(small))
                            .await?;
                    let first = send_positioned(&mut channel, b"first".to_vec()).await;
                    first_at.store(first.seq, Ordering::SeqCst);
                    read_first.wait().await;
                    away.wait().await;
                    until_offline(server_of(&server_remote), member_cid.load(Ordering::SeqCst))
                        .await;
                    for n in 0..6u64 {
                        let at = send_positioned(&mut channel, n.to_string().into_bytes()).await;
                        if n == 3 {
                            three_at.store(at.seq, Ordering::SeqCst);
                        }
                    }
                    sent.wait().await;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (read_first, away, sent, done) =
                (read_first.clone(), away.clone(), sent.clone(), done.clone());
            let (member_cid, read) = (member_cid.clone(), read.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut first) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    let _ = read_until(&mut first, "first").await;
                    read_first.wait().await;
                    conn.disconnect().await?;
                    away.wait().await;
                    sent.wait().await;
                    let conn = connect(&remote, &me).await?;
                    drop(first);
                    let mut channel = next_group_channel(&mut events, "member").await;
                    *read.lock().unwrap() = read_until(&mut channel, "5").await;
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let read = read.lock().unwrap().clone();
        let (first, three) = (
            first_at.load(Ordering::SeqCst),
            three_at.load(Ordering::SeqCst),
        );
        assert_eq!(
            read.first(),
            Some(&Read::Broken {
                last: first,
                earliest: three
            }),
            "the lost positions were not named first: {read:?}"
        );
        assert_eq!(texts(&read), vec!["3", "4", "5"]);
        assert_eq!(seqs(&read), vec![three, three + 1, three + 2]);
    }
}
