#![cfg(not(target_family = "wasm"))]
//! A native client reaches a server by WebSocket URL: it registers to `ws://host:port/path`,
//! and a later credentialed login — which names no address at all — dials the same URL again,
//! because the account remembers it.
//!
//! The server listens for WebSocket connections only on the port the URL names; that port sends
//! no `FirstPacket`, so a client that fell back to the plain TCP dial of the stored address would
//! hang in the first-packet read and fail here.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::WebSocketEndpoint;
    use citadel_sdk::prelude::*;
    use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
    use citadel_sdk::test_common::server_test_node_with_websocket;
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    async fn echo_once(conn: &mut CitadelClientServerConnection<StackedRatchet>, text: &str) {
        let (mut tx, mut rx) = conn.take_channel().expect("channel").split();
        tx.send(SecBuffer::from(text.as_bytes()))
            .await
            .expect("send");
        let echoed = rx.next().await.expect("echo");
        assert_eq!(echoed.as_ref(), text.as_bytes());
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn register_and_login_over_a_websocket_url() {
        citadel_logging::setup_log();

        let server_kernel = ClientConnectListenerKernel::<_, _, StackedRatchet>::new(
            |mut connection: CitadelClientServerConnection<StackedRatchet>| async move {
                let (mut tx, mut rx) = connection.take_channel().unwrap().split();
                while let Some(msg) = rx.next().await {
                    tx.send(msg).await?;
                }
                Ok(())
            },
        );
        let ((server, _tcp_addr), ws_addr) =
            server_test_node_with_websocket(server_kernel, |builder| {
                let _ = builder.with_backend(BackendType::InMemory);
            });

        // A path, as a Worker route has one; the native listener ignores it.
        let endpoint =
            WebSocketEndpoint::parse(&format!("ws://127.0.0.1:{}/acme", ws_addr.port())).unwrap();
        let username = format!("ws_{}", &Uuid::new_v4().to_string()[..8]);
        let password = "password123";

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                let registered = remote
                    .register_to_endpoint(
                        endpoint,
                        username.as_str(),
                        username.as_str(),
                        password,
                        Default::default(),
                        None,
                    )
                    .await?;

                let mut first = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                assert_eq!(first.cid, registered.cid);
                echo_once(&mut first, "over the url").await;
                first.disconnect().await?;

                let mut second = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                assert_eq!(second.cid, registered.cid);
                echo_once(&mut second, "and again after a reconnect").await;
                second.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default()
            .with_backend(BackendType::InMemory)
            .build(client_kernel)
            .unwrap();

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = client => client_res
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("timed out");
        assert!(result.is_ok(), "failed: {result:?}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_url_nothing_listens_on_is_refused_not_hung() {
        citadel_logging::setup_log();
        let port = citadel_wire::socket_helpers::get_tcp_listener("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let endpoint = WebSocketEndpoint::parse(&format!("ws://127.0.0.1:{port}/")).unwrap();

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                let result = remote
                    .register_to_endpoint(
                        endpoint,
                        "nobody_home",
                        "nobody_home",
                        "password123",
                        Default::default(),
                        None,
                    )
                    .await;
                assert!(result.is_err(), "registering to a dead URL must fail");
                remote.shutdown().await
            },
        );
        let client = DefaultNodeBuilder::default()
            .with_backend(BackendType::InMemory)
            .build(client_kernel)
            .unwrap();
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(30), client)
            .await
            .expect("timed out");
        assert!(result.is_ok(), "failed: {result:?}");
    }
}
