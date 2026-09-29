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

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::future::BoxFuture;
    use futures::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    type Peer = Arc<
        dyn Fn(usize, PeerConnectSuccess<StackedRatchet>) -> BoxFuture<'static, ()> + Send + Sync,
    >;

    /// Runs two peers behind a test server; `peer` gets each side's connection as it arrives.
    async fn run_pair(turn: Option<TurnRelayConfig>, peer: Peer) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let finished = Arc::new(AtomicUsize::new(0));
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();
        for me in 0..2 {
            let mut setup = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled);
            if let Some(turn) = turn.clone() {
                setup = setup.with_turn_config(turn);
            }
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let peer = peer.clone();
            let finished = finished.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    peer(me, conn).await;
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        // A hang guard for the whole pair, not a latency assertion.
        let result = tokio::time::timeout(
            Duration::from_secs(150),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }

    fn data(seq: u32) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&seq.to_be_bytes());
        out
    }

    fn end(total: u32) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&total.to_be_bytes());
        out
    }

    /// Reads a stream written with [`data`]/[`end`]: every sequence number exactly once, in order.
    async fn receive_in_order(rx: &mut PeerChannelRecvHalf<StackedRatchet>, who: usize) -> u32 {
        let mut next = 0u32;
        loop {
            let msg = rx.next().await.expect("channel closed mid-stream");
            let bytes = msg.as_ref();
            let n = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
            match bytes[0] {
                0 => {
                    assert_eq!(n, next, "peer {who}: message out of order or duplicated");
                    next += 1;
                }
                _ => {
                    assert_eq!(
                        n, next,
                        "peer {who}: messages missing before the end marker"
                    );
                    return next;
                }
            }
        }
    }

    /// A TURN relay that silently drops every packet: the direct attempt is skipped (relay-only)
    /// and the relay attempt runs until it gives up, so the campaign is still running when the
    /// application gets its channel and then fails.
    fn black_hole_relay() -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![TurnServerCredential::new(
                "turn:192.0.2.1:3478?transport=udp",
                "user",
                "pass",
                None,
            )
            .unwrap()],
            TurnPolicy::RelayOnly,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_channel_is_usable_over_the_relay_while_punching_runs_and_then_fails() {
        run_pair(
            Some(black_hole_relay()),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn losing_the_direct_path_falls_back_to_the_relay_without_loss() {
        run_pair(
            None,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
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
                                    assert!(cell.sever_p2p_route_for_testing());
                                }
                            }
                            assert_eq!(next, TOTAL);
                        }
                    };
                    let (fell_back, ()) = tokio::join!(saw_fall_back, conversation);
                    fell_back.expect("path watch closed");
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
