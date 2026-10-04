#![cfg(not(target_family = "wasm"))]
//! `probe_server` round-trips an authenticated probe to the server now, over the plain transport
//! and over a WebSocket, without disturbing the session: the channel still echoes afterwards.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::WebSocketEndpoint;
    use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node_with_websocket;
    use futures::StreamExt;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    async fn echo_once(conn: &mut CitadelClientServerConnection<StackedRatchet>) {
        let (mut tx, mut rx) = conn.take_channel().expect("channel").split();
        tx.send(SecBuffer::from(&b"still alive"[..]))
            .await
            .expect("send");
        assert_eq!(rx.next().await.expect("echo").as_ref(), b"still alive");
    }

    async fn probes_answer(remote: &NodeRemote<StackedRatchet>, cid: u64) {
        for _ in 0..3 {
            match remote.probe_server(cid, PROBE_TIMEOUT).await {
                ServerProbeOutcome::Ok(rtt) => assert!(rtt < PROBE_TIMEOUT, "{rtt:?}"),
                other => panic!("a connected server must answer a probe: {other:?}"),
            }
        }
        // A zero budget cannot be met by any network round trip: it reports Timeout, not Ok.
        let outcome = remote.probe_server(cid, Duration::ZERO).await;
        assert!(
            matches!(outcome, ServerProbeOutcome::Timeout),
            "{outcome:?}"
        );
        let outcome = remote.probe_server(cid ^ 1, PROBE_TIMEOUT).await;
        assert!(
            matches!(outcome, ServerProbeOutcome::Error(_)),
            "no session, no probe: {outcome:?}"
        );
    }

    async fn run(
        dial: Option<WebSocketEndpoint>,
        tcp_addr: SocketAddr,
    ) -> Result<(), NetworkError> {
        let username = format!("probe_{}", &Uuid::new_v4().to_string()[..8]);
        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                match dial {
                    Some(endpoint) => {
                        let _ = remote
                            .register_to_endpoint(
                                endpoint,
                                username.as_str(),
                                username.as_str(),
                                "password123",
                                Default::default(),
                                None,
                            )
                            .await?;
                    }
                    None => {
                        let _ = remote
                            .register_with_defaults(
                                tcp_addr,
                                username.as_str(),
                                username.as_str(),
                                "password123",
                            )
                            .await?;
                    }
                }
                let mut conn = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        "password123",
                    ))
                    .await?;
                probes_answer(&remote, conn.cid).await;
                echo_once(&mut conn).await;
                conn.shutdown_kernel().await
            },
        );
        let client = DefaultNodeBuilder::default()
            .with_backend(BackendType::InMemory)
            .build(client_kernel)
            .unwrap();
        client.await.map(|_| ())
    }

    async fn with_server(websocket: bool) {
        citadel_logging::setup_log();
        let echo_server = ClientConnectListenerKernel::<_, _, StackedRatchet>::new(
            |mut connection: CitadelClientServerConnection<StackedRatchet>| async move {
                let (mut tx, mut rx) = connection.take_channel().unwrap().split();
                while let Some(msg) = rx.next().await {
                    tx.send(msg).await?;
                }
                Ok(())
            },
        );
        let ((server, tcp_addr), ws_addr) =
            server_test_node_with_websocket(echo_server, |builder| {
                let _ = builder.with_backend(BackendType::InMemory);
            });
        let dial = websocket.then(|| {
            WebSocketEndpoint::parse(&format!("ws://127.0.0.1:{}/probe", ws_addr.port())).unwrap()
        });
        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.is_ok()))),
                client_res = run(dial, tcp_addr) => client_res
            }
        };
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("timed out");
        assert!(result.is_ok(), "failed: {result:?}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_probe_round_trips_over_the_default_transport() {
        with_server(false).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_probe_round_trips_over_a_websocket() {
        with_server(true).await;
    }
}
