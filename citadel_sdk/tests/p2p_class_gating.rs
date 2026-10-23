//! A class of traffic the server's path policy keeps off a path is refused there, with a typed
//! error, and the classes the path does carry keep flowing.
//!
//! ```text
//! policy: Direct disabled; the server relay carries Control only (Msg, File, Media on Turn)
//!   pair without TURN → plan is the server relay alone → a message and a file are refused
//! policy: Direct disabled; the server relay carries no Media
//!   → a media endpoint is refused ("can't connect a call"), messages still flow
//! ```
//! Control: without a stamped plan every class rides every path (`ClassGates::OPEN`, the unit
//! tests of `class_gates`), which every other SDK test exercises.
#![cfg(not(target_family = "wasm"))]

mod common;
mod relay_pair;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::media::test_media_config;
    use crate::relay_pair::pair::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::media::MediaEndpoint;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;

    /// Direct disabled; every other path carries every class, except that the server relay
    /// carries only `relay`.
    fn policy(relay: PathClasses) -> PathPolicy {
        let rules = PathKind::ALL
            .into_iter()
            .map(|kind| PathRule {
                kind,
                enabled: kind != PathKind::Direct,
                attempt_timeout: Duration::from_secs(30),
                cost_weight: 1,
                classes: if kind == PathKind::ServerRelay {
                    relay
                } else {
                    PathClasses::ALL
                },
            })
            .collect();
        PathPolicy::new(rules, PathClasses::NONE).unwrap()
    }

    fn server(
        policy: PathPolicy,
    ) -> (
        NodeFuture<'static, EmptyKernel<StackedRatchet>>,
        std::net::SocketAddr,
    ) {
        server_test_node(EmptyKernel::<StackedRatchet>::default(), move |builder| {
            let _ = builder.with_path_policy(policy);
        })
    }

    fn code(result: Result<(), NetworkError>) -> Option<ErrorCode> {
        result.err().map(|err| err.code())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn messages_and_files_are_refused_on_a_relay_that_carries_neither() {
        let file = std::env::temp_dir().join(format!("gating_{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&file, vec![7u8; 4096]).unwrap();
        let written = file.clone();
        run_pair_on(
            server(policy(PathClasses::of(&[PathClass::Control]))),
            None,
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                let file = file.clone();
                Box::pin(async move {
                    assert_eq!(conn.channel.p2p_path(), P2pPath::ServerRelay);
                    assert!(!conn.channel.path_permits(PathClass::Msg), "peer {me}");
                    // A file send's refusal reaches the caller through the kernel as text (an
                    // InternalServerError carries no code), so it is matched by its form.
                    let refused = conn
                        .remote
                        .send_file(file)
                        .await
                        .expect_err("a file must not ride this relay");
                    assert!(
                        refused
                            .to_string()
                            .contains("may not carry File traffic (ServerRelay)"),
                        "peer {me}: {refused}"
                    );
                    let (mut tx, _rx) = conn.channel.split();
                    let sent = tx.send(b"over the relay".to_vec()).await;
                    assert_eq!(code(sent), Some(ErrorCode::PathClassDenied), "peer {me}");
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
        std::fs::remove_file(written).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_call_is_refused_on_a_relay_that_carries_no_media() {
        let relay = PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
        run_pair_on(
            server(policy(relay)),
            None,
            UdpMode::Enabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    assert!(conn.channel.path_permits(PathClass::Msg));
                    assert!(!conn.channel.path_permits(PathClass::Media), "peer {me}");
                    let mut cfg = test_media_config();
                    cfg.udp_wait = Duration::from_millis(200);
                    let refused = MediaEndpoint::from_peer_connection(conn, cfg).await;
                    let err = refused.expect_err("media must not ride this relay");
                    assert_eq!(err.code(), ErrorCode::PathClassDenied, "peer {me}");
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
    }

    /// A refused call must not depend on the peer. Each side used to negotiate the transport
    /// first and check the gate after, so the side refused first dropped its channel while its
    /// offer could still be queued, and the other side then failed with `MediaTransportClosed`
    /// instead of the refusal. Peer 0 here is that first side, gone before peer 1 calls.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_call_is_refused_even_after_the_peer_has_gone() {
        let relay = PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
        let (gone_tx, gone_rx) = tokio::sync::watch::channel(false);
        let gone_tx = Arc::new(gone_tx);
        run_pair_on(
            server(policy(relay)),
            None,
            UdpMode::Enabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                let (gone_tx, mut gone_rx) = (gone_tx.clone(), gone_rx.clone());
                Box::pin(async move {
                    if me == 0 {
                        drop(conn);
                        let _ = gone_tx.send(true);
                    } else {
                        let _ = gone_rx.wait_for(|gone| *gone).await;
                        let mut cfg = test_media_config();
                        cfg.udp_wait = Duration::from_millis(200);
                        let refused = MediaEndpoint::from_peer_connection(conn, cfg).await;
                        let err = refused.expect_err("media must not ride this relay");
                        assert_eq!(err.code(), ErrorCode::PathClassDenied, "{err}");
                    }
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_classes_a_relay_carries_still_flow() {
        let relay = PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
        run_pair_on(
            server(policy(relay)),
            None,
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    let (mut tx, mut rx) = conn.channel.split();
                    tx.send(format!("hello from {me}").into_bytes())
                        .await
                        .unwrap();
                    let heard = rx.next().await.expect("the relay carries messages");
                    assert_eq!(heard.as_ref(), format!("hello from {}", 1 - me).as_bytes());
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
    }
}
