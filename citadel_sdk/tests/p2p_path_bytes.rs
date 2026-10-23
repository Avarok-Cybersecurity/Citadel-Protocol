//! Every P2P connection counts the bytes it sends and receives on each path
//! (`PeerChannel::path_bytes`), every node counts its traffic by class (`NodeRemote::traffic`),
//! and a server counts the P2P traffic it relays apart from its own client-server traffic.
//!
//! No assertion here is a latency: each is an attribution, a growth or a bound.
#![cfg(not(target_family = "wasm"))]

mod relay_pair;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::relay_pair::pair::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const MESSAGES: u32 = 20;

    /// Sends [`MESSAGES`] messages each way and returns once the peer's have all arrived. The
    /// channel is returned, for the caller to keep open until its peer is done too.
    async fn exchange(conn: PeerConnectSuccess<StackedRatchet>, me: usize) -> impl Drop {
        let (mut tx, mut rx) = conn.channel.split();
        let send = async {
            for seq in 0..MESSAGES {
                tx.send(data(seq)).await.unwrap();
            }
            tx.send(end(MESSAGES)).await.unwrap();
        };
        let (_, received) = tokio::join!(send, receive_in_order(&mut rx, me));
        assert_eq!(received, MESSAGES);
        Box::new((tx, rx))
    }

    /// Every field of `after` is at least its field in `before`.
    fn grew_or_held(before: PathBytesSnapshot, after: PathBytesSnapshot) {
        for path in [P2pPath::Direct, P2pPath::Turn, P2pPath::ServerRelay] {
            let (b, a) = (before.on(path), after.on(path));
            assert!(a.tx >= b.tx && a.rx >= b.rx, "{path:?}: {a:?} after {b:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_direct_connection_counts_its_traffic_on_the_direct_path() {
        run_pair(
            None,
            UdpMode::Disabled,
            Arc::new(|me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    let node = conn.remote.remote().clone();
                    assert_eq!(cell.ensure_direct().await.unwrap(), P2pPath::Direct);
                    wait_for_peers().await;
                    let before = cell.bytes();
                    let _open = exchange(conn, me).await;
                    let after = cell.bytes();
                    grew_or_held(before, after);
                    let minimum = u64::from(MESSAGES) * data(0).len() as u64;
                    assert!(
                        after.direct.tx - before.direct.tx >= minimum,
                        "peer {me}: {before:?} -> {after:?}"
                    );
                    assert!(after.direct.rx - before.direct.rx >= minimum, "peer {me}");
                    assert_eq!(after.turn, ByteCount::default(), "peer {me}");
                    let traffic = node.traffic();
                    assert!(traffic.direct.tx >= after.direct.tx, "peer {me}");
                    assert!(traffic.direct.rx >= after.direct.rx, "peer {me}");
                    assert_eq!(traffic.turn, ByteCount::default());
                    assert!(traffic.client_server.tx > 0 && traffic.client_server.rx > 0);
                    wait_for_peers().await;
                })
            }),
        )
        .await;
    }

    /// A server that keeps its remote, to read its traffic.
    #[derive(Clone, Default)]
    struct Tapped(Arc<Mutex<Option<NodeRemote<StackedRatchet>>>>);

    impl Tapped {
        fn traffic(&self) -> NodeTrafficSnapshot {
            self.0
                .lock()
                .unwrap()
                .as_ref()
                .expect("server not loaded")
                .traffic()
        }
    }

    #[async_trait]
    impl NetKernel<StackedRatchet> for Tapped {
        fn load_remote(&mut self, remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
            *self.0.lock().unwrap() = Some(remote);
            Ok(())
        }
        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn on_node_event_received(
            &self,
            _: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    /// A TURN relay that refuses at once, so the connection stays on the server relay.
    fn refusing_relay() -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![
                TurnServerCredential::new("turn:127.0.0.1:1?transport=tcp", "user", "pass", None)
                    .unwrap(),
            ],
            TurnPolicy::RelayOnly,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relayed_traffic_is_counted_by_both_peers_and_the_server_that_relays_it() {
        let server = Tapped::default();
        let tap = server.clone();
        let relayed: Arc<Mutex<[PathBytesSnapshot; 2]>> = Default::default();
        run_pair_on(
            server_test_node(server, |_| {}),
            Some(refusing_relay()),
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                let (tap, relayed) = (tap.clone(), relayed.clone());
                Box::pin(async move {
                    let cell = conn.channel.p2p_path_cell();
                    assert!(cell.ensure_direct().await.is_err());
                    let before = cell.bytes();
                    let _open = exchange(conn, me).await;
                    let after = cell.bytes();
                    grew_or_held(before, after);
                    let minimum = u64::from(MESSAGES) * data(0).len() as u64;
                    let relay = after.server_relay;
                    assert!(relay.tx - before.server_relay.tx >= minimum, "peer {me}");
                    assert!(relay.rx - before.server_relay.rx >= minimum, "peer {me}");
                    assert_eq!((after.direct, after.turn), Default::default(), "peer {me}");
                    relayed.lock().unwrap()[me] = after;
                    wait_for_peers().await;

                    // The server counts each relayed packet once in and once out. It may still
                    // be forwarding the last of them, so this waits (bounded: a hang guard).
                    let [a, b] = *relayed.lock().unwrap();
                    let sent = a.server_relay.tx + b.server_relay.tx;
                    let received = a.server_relay.rx + b.server_relay.rx;
                    let counted = tokio::time::timeout(Duration::from_secs(20), async {
                        loop {
                            let t = tap.traffic();
                            if t.relayed_p2p.rx >= sent && t.relayed_p2p.tx >= received {
                                return t;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await;
                    let t = counted.unwrap_or_else(|_| {
                        panic!(
                            "server counted {:?}, peers {sent}/{received}",
                            tap.traffic()
                        )
                    });
                    assert_eq!((t.direct, t.turn), Default::default());
                    assert!(t.client_server.tx > 0 && t.client_server.rx > 0);
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
    }
}
