//! Dropping a UDP channel that a recovery already replaced must not close the replacement.
//!
//! A recovery that restores UDP (`PathControl::upgrade(true)`) installs a new channel for the same
//! P2P connection and hands it out on `take_restored_udp`. The old channel's receive half still
//! sends `DisconnectUDP` when it is dropped, and that signal names the CONNECTION, not the
//! channel, so a drop that came after the restore closed the new channel on both peers: its
//! stream ended at once. An application that moves a live call to the restored channel drops the
//! old half exactly then (the agent's `rebind_transport` aborts the old pump after adopting the
//! new one), so every call that survived a path loss lost its media a moment later.
//!
//! `p2p_path_rearm` drops the old halves before the restore arrives and so never saw this; this
//! test drops them after, and requires a datagram to cross the restored channel both ways.
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
    use std::time::Duration;

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_old_udp_halves_after_a_restore_keeps_the_new_channel() {
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
                        control.upgrade(true).expect("the campaign is retrying");
                    }
                    let udp = restored.recv().await.expect("a restored UDP channel");
                    // The order an application that moves a live call uses: the old halves
                    // outlive the restore.
                    drop((first_tx, first_rx));
                    wait_for_peers().await;
                    let (udp_tx, mut udp_rx) = udp.split();
                    udp_tx.unbounded_send(&b"datagram"[..]).unwrap();
                    let got = tokio::time::timeout(Duration::from_secs(10), udp_rx.next())
                        .await
                        .expect("no datagram crossed the restored channel")
                        .expect("the restored UDP channel ended");
                    assert_eq!(got.as_ref(), b"datagram", "peer {me}");
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }
}
