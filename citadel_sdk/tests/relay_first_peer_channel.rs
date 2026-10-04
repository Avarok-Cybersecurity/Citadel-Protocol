//! A peer connection is usable the moment it exists, over the server relay; NAT traversal runs in
//! the background and upgrades the channel in place.
//!
//! - the channel arrives while the upgrade campaign is still running, carries traffic both ways
//!   over the relay, and `ensure_direct` reports the campaign's failure instead of hanging;
//! - when the direct path does attach, every message sent before, during and after the switch
//!   arrives exactly once and in order;
//! - a message sent the instant the channel arrives is delivered (the initiator is released only
//!   once the receiver's virtual connection exists);
//! - losing the direct path mid-conversation falls back to the relay with nothing lost, the
//!   channel stays open, and the bounded retry restores the direct path.
//!
//! No assertion here is a latency: each is an ordering or an outcome.
#![cfg(not(target_family = "wasm"))]

mod relay_pair;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::relay_pair::pair::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::wait_for_peers;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn the_channel_is_usable_over_the_relay_while_punching_runs_and_then_fails() {
        run_pair(
            Some(black_hole_relay()),
            UdpMode::Disabled,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    let at_receipt = cell.status();
                    assert_eq!(at_receipt.path, P2pPath::ServerRelay, "peer {me}");
                    assert!(
                        at_receipt.upgrading,
                        "peer {me}: the channel must arrive before the upgrade campaign ends"
                    );
                    let (mut tx, mut rx) = conn.channel.split();
                    const N: u32 = 20;
                    let send = async {
                        for seq in 0..N {
                            tx.send(data(seq)).await.unwrap();
                        }
                        tx.send(end(N)).await.unwrap();
                    };
                    let (_, received) = tokio::join!(send, receive_in_order(&mut rx, me));
                    assert_eq!(received, N);
                    assert!(
                        cell.status().upgrading,
                        "peer {me}: traffic must have flowed while the campaign was still running"
                    );

                    let outcome = cell.ensure_direct().await;
                    assert!(outcome.is_err(), "peer {me}: {outcome:?}");
                    assert_eq!(cell.status().path, P2pPath::ServerRelay);
                    assert!(!cell.status().upgrading);

                    // The campaign's end changes nothing about the channel itself.
                    wait_for_peers().await;
                    tx.send(end(0)).await.unwrap();
                    assert_eq!(receive_in_order(&mut rx, me).await, 0);
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn messages_sent_across_the_upgrade_arrive_once_and_in_order() {
        run_pair(
            None,
            UdpMode::Disabled,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    let (mut tx, mut rx) = conn.channel.split();
                    const AFTER: u32 = 50;
                    // Paced by the peer's progress (at most WINDOW ahead of what we have
                    // received), so the stream never floods the relay the punch is coordinated
                    // over.
                    const WINDOW: u32 = 8;
                    let upgrade_failed = AtomicBool::new(false);
                    let (progress_tx, mut progress) = tokio::sync::watch::channel((0u32, false));
                    let send = async {
                        let (mut seq, mut on_relay, mut on_p2p) = (0u32, 0u32, 0u32);
                        while on_p2p < AFTER && !upgrade_failed.load(Ordering::SeqCst) {
                            let path = cell.get();
                            tx.send(data(seq)).await.unwrap();
                            seq += 1;
                            if path == P2pPath::ServerRelay {
                                on_relay += 1;
                            } else {
                                on_p2p += 1;
                            }
                            progress
                                .wait_for(|(got, ended)| *ended || got + WINDOW > seq)
                                .await
                                .unwrap();
                        }
                        tx.send(end(seq)).await.unwrap();
                        (seq, on_relay, on_p2p)
                    };
                    let receive = async {
                        let mut next = 0u32;
                        loop {
                            let msg = rx.next().await.expect("channel closed mid-stream");
                            let bytes = msg.as_ref();
                            let n = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
                            assert_eq!(n, next, "peer {me}: lost, duplicated or out of order");
                            if bytes[0] == 1 {
                                progress_tx.send_replace((next, true));
                                return next;
                            }
                            next += 1;
                            progress_tx.send_replace((next, false));
                        }
                    };
                    let upgrade = async {
                        let outcome = cell.ensure_direct().await;
                        if outcome.is_err() {
                            upgrade_failed.store(true, Ordering::SeqCst);
                        }
                        outcome
                    };
                    let ((sent, on_relay, on_p2p), received, upgraded) =
                        tokio::join!(send, receive, upgrade);
                    assert_eq!(upgraded.unwrap(), P2pPath::Direct, "peer {me}");
                    assert!(
                        on_relay > 0,
                        "peer {me}: nothing was sent before the switch"
                    );
                    assert_eq!(on_p2p, AFTER);
                    assert!(sent > AFTER);
                    assert!(received > AFTER, "peer {me} received {received}");
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_sent_the_instant_the_channel_arrives_is_delivered() {
        run_pair(
            None,
            UdpMode::Disabled,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let (mut tx, mut rx) = conn.channel.split();
                    // No barrier, no wait: the first thing either side does is send.
                    tx.send(data(0)).await.unwrap();
                    tx.send(end(1)).await.unwrap();
                    assert_eq!(receive_in_order(&mut rx, me).await, 1);
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }

    /// The direct path dies the way a network path does: both peers' QUIC sockets stop carrying
    /// anything, with no close or reset sent. QUIC notices by its idle timeout, the SDK falls back
    /// to the relay, and nothing sent in the meantime may be lost.
    ///
    /// Unix only: the path is cut at the OS level (see [`kill_udp_socket`]).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn losing_the_direct_path_falls_back_to_the_relay_without_loss() {
        run_pair(
            None,
            // The UDP channel exposes the direct path's socket addresses, which is how the test
            // finds the sockets to cut.
            UdpMode::Enabled,
            Arc::new(|me, mut conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    let udp = conn
                        .udp_channel_rx
                        .take()
                        .expect("UDP mode is enabled")
                        .await
                        .expect("the direct path carries a UDP channel");
                    let (udp_tx, udp_rx) = udp.split();
                    let direct_ends = (udp_tx.local_addr(), udp_tx.remote_addr());
                    wait_for_peers().await;
                    let mut changes = conn.channel.path_changes();
                    let (mut tx, mut rx) = conn.channel.split();
                    const TOTAL: u32 = 2000;
                    const SEVER_AFTER: u32 = 100;
                    // Both ends must observe the fall-back as an event; watched from the start so
                    // the later retry cannot hide it.
                    let saw_fall_back = async {
                        changes
                            .wait_for(|status| status.path == P2pPath::ServerRelay)
                            .await
                            .map(|_| ())
                    };
                    let conversation = async {
                        if me == 0 {
                            // Streams without pause, so messages are in flight when the path dies.
                            for seq in 0..TOTAL {
                                tx.send(data(seq)).await.unwrap();
                            }
                            tx.send(end(TOTAL)).await.unwrap();
                        } else {
                            let mut next = 0u32;
                            loop {
                                let msg = rx.next().await.expect("channel closed mid-stream");
                                let bytes = msg.as_ref();
                                let n = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
                                assert_eq!(n, next, "message lost, duplicated or reordered");
                                if bytes[0] == 1 {
                                    break;
                                }
                                next += 1;
                                if next == SEVER_AFTER {
                                    // The peer is mid-stream: its later messages are in flight.
                                    // Both ends of the direct path live in this process.
                                    let (local, remote) = direct_ends;
                                    assert!(kill_udp_socket(local) > 0, "no socket at {local}");
                                    assert!(kill_udp_socket(remote) > 0, "no socket at {remote}");
                                }
                            }
                            assert_eq!(next, TOTAL);
                        }
                    };
                    let (fell_back, ()) = tokio::join!(saw_fall_back, conversation);
                    fell_back.expect("path watch closed");
                    drop((udp_tx, udp_rx));
                    // The channel stayed open: the receiver answers over it.
                    if me == 1 {
                        tx.send(end(0)).await.unwrap();
                    } else {
                        assert_eq!(receive_in_order(&mut rx, me).await, 0);
                    }
                    // The bounded retry restores the direct path.
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }
}
