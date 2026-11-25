#![cfg(not(target_family = "wasm"))]
//! A member back in a replay group is replayed from the last position it holds, in order and
//! before anything live, turn by turn. Between turns the node's group order lock is free: the
//! group's own traffic is positioned while the replay waits, and reaches the member after it.
//!
//! ```text
//! O, M: register → connect → befriend; O creates a replay group inviting M; M joins
//! O sends "first"; M reads it, then disconnects; O sends "0".."599" while M is away
//! O holds the server between replay turns; M reconnects
//! at the first turn O sends "live" and is answered while the replay waits; O lets it go on
//! M reads "0".."599" then "live", one position after another, and fetches no gap
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_replay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::{gap_fetches, observe_replay_turns, pause_replay_turns};
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    const AWAY: usize = 600;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_long_replay_is_in_order_and_lets_the_group_through_between_turns() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, server_remote) = replay_server();
        let owner_name = format!("rto_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("rtm_{}", &Uuid::new_v4().to_string()[..8]);
        let member_cid = Arc::new(AtomicU64::new(0));
        let (read_first, away, sent, done) = (
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
            Arc::new(Barrier::new(2)),
        );
        let read = Arc::new(Mutex::new(Vec::new()));
        let key = Arc::new(Mutex::new(None));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (read_first, away, sent, done) =
                (read_first.clone(), away.clone(), sent.clone(), done.clone());
            let (member_cid, server_remote) = (member_cid.clone(), server_remote.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let (conn, mut channel) =
                        open_group(&remote, server_addr, (&me, &peer), replay_options(LOG)).await?;
                    let _ = send_positioned(&mut channel, b"first".to_vec()).await;
                    read_first.wait().await;
                    away.wait().await;
                    until_offline(server_of(&server_remote), member_cid.load(Ordering::SeqCst))
                        .await;
                    for n in 0..AWAY {
                        let _ = send_positioned(&mut channel, n.to_string().into_bytes()).await;
                    }
                    let pause = pause_replay_turns();
                    let mut turns = observe_replay_turns();
                    sent.wait().await;
                    let turn = tokio::time::timeout(REJOIN_DEADLINE, turns.recv())
                        .await
                        .expect("the member's replay never finished a turn")
                        .expect("the replay observer closed");
                    assert!(
                        turn.sent > 0 && turn.sent < AWAY,
                        "one turn sent {}",
                        turn.sent
                    );
                    let live = send_positioned(&mut channel, b"live".to_vec());
                    let _ = tokio::time::timeout(REJOIN_DEADLINE, live)
                        .await
                        .expect("nothing was positioned while the replay waited between turns");
                    pause.release();
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
            let (member_cid, read, key) = (member_cid.clone(), read.clone(), key.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut first) =
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?;
                    member_cid.store(conn.cid, Ordering::SeqCst);
                    *key.lock().unwrap() = Some(first.key());
                    let _ = read_until(&mut first, "first").await;
                    read_first.wait().await;
                    conn.disconnect().await?;
                    away.wait().await;
                    sent.wait().await;
                    let conn = connect(&remote, &me).await?;
                    drop(first);
                    let mut channel = next_group_channel(&mut events, "member").await;
                    *read.lock().unwrap() = read_until(&mut channel, "live").await;
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let read = read.lock().unwrap().clone();
        let mut wanted: Vec<String> = (0..AWAY).map(|n| n.to_string()).collect();
        wanted.push("live".to_string());
        assert_eq!(
            texts(&read),
            wanted,
            "not replayed in order before what was live"
        );
        let seqs = seqs(&read);
        assert!(
            seqs.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "positions skipped or repeated: {seqs:?}"
        );
        let key = key.lock().unwrap().expect("the member never joined");
        assert_eq!(
            gap_fetches(key),
            0,
            "the replay left a gap the member fetched"
        );
    }
}
