//! `PeerChannel::upgrade` re-arms a P2P path campaign:
//!
//! - a campaign that gave up parks rather than ending, and one peer's upgrade wakes BOTH peers'
//!   campaigns, which then report the retry on their path cells as always — as often as asked;
//! - a recovery asked to restore UDP, on a connection that began with it, gives both peers a new
//!   UDP channel on `take_restored_udp`, and a datagram crosses it.
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
    use std::sync::Arc;

    /// A TURN relay that refuses at once (a TCP port nothing listens on), so every relay-only
    /// attempt fails in milliseconds rather than at the relay timeout.
    fn refusing_relay() -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![
                TurnServerCredential::new("turn:127.0.0.1:1?transport=tcp", "user", "pass", None)
                    .unwrap(),
            ],
            TurnPolicy::RelayOnly,
        )
    }

    /// Waits for the cell to report a campaign that is running, then one that has stopped.
    async fn sees_a_retry_run_and_stop(changes: &mut tokio::sync::watch::Receiver<P2pPathStatus>) {
        changes.wait_for(|s| s.upgrading).await.expect("cell gone");
        changes.wait_for(|s| !s.upgrading).await.expect("cell gone");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_peers_upgrade_re_arms_both_campaigns_after_they_gave_up() {
        run_pair(
            Some(refusing_relay()),
            UdpMode::Disabled,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    assert!(
                        cell.ensure_direct().await.is_err(),
                        "peer {me}: nothing to attach"
                    );
                    assert!(!cell.status().upgrading);
                    let control = conn.channel.path_control();
                    let mut changes = conn.channel.path_changes();
                    for round in 0..2 {
                        wait_for_peers().await;
                        changes.borrow_and_update();
                        if me == 0 {
                            control
                                .upgrade(false)
                                .unwrap_or_else(|err| panic!("round {round}: {err:?}"));
                        }
                        // Peer 1 never asked, and its campaign retries too.
                        sees_a_retry_run_and_stop(&mut changes).await;
                        assert_eq!(cell.status().path, P2pPath::ServerRelay, "peer {me}");
                    }
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }

    /// The direct path dies (as in `relay_first_peer_channel`); peer 0 asks for UDP back while the
    /// campaign is still waiting to retry, and both peers get a new UDP channel with the route.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_recovery_asked_for_udp_restores_it_on_both_peers() {
        run_pair(
            None,
            UdpMode::Enabled,
            Arc::new(|me, mut conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    let first = conn
                        .udp_channel_rx
                        .take()
                        .expect("UDP mode is enabled")
                        .await
                        .expect("the direct path carries a UDP channel");
                    let mut restored = conn.channel.take_restored_udp().expect("a P2P channel");
                    let (first_tx, first_rx) = first.split();
                    let direct_ends = (first_tx.local_addr(), first_tx.remote_addr());
                    let mut changes = conn.channel.path_changes();
                    let control = conn.channel.path_control();
                    wait_for_peers().await;
                    if me == 1 {
                        // Both ends of the direct path live in this process.
                        let (local, remote) = direct_ends;
                        assert!(kill_udp_socket(local) > 0, "no socket at {local}");
                        assert!(kill_udp_socket(remote) > 0, "no socket at {remote}");
                    }
                    changes
                        .wait_for(|s| s.path == P2pPath::ServerRelay)
                        .await
                        .expect("cell gone");
                    if me == 0 {
                        // The campaign waits its backoff before the retry's rendezvous.
                        control.upgrade(true).expect("the campaign is retrying");
                    }
                    drop((first_tx, first_rx));
                    let udp = restored.recv().await.expect("a restored UDP channel");
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    let (udp_tx, mut udp_rx) = udp.split();
                    wait_for_peers().await;
                    udp_tx.unbounded_send(&b"datagram"[..]).unwrap();
                    let got = udp_rx.next().await.expect("the restored UDP channel ended");
                    assert_eq!(got.as_ref(), b"datagram", "peer {me}");
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }
}
