#![cfg(not(target_family = "wasm"))]
//! A client whose link closes cleanly can connect again straight away.
//!
//! A server read loop ended by a clean EOF waited for every in-flight packet
//! handler to finish, and the keep-alive handler sleeps for the whole keep-alive
//! interval (15 minutes) before replying. So a FIN from the client left its
//! session registered, and every reconnect was refused with "Session Already
//! Connected" until that sleep ran out. A reset was not affected: an I/O error
//! short-circuits the loop.
//!
//! It was found on Cloudflare, where a WebSocket close is the only way a dropped
//! client ever reaches the server, so every drop was a clean EOF and every drop
//! locked the account out. Here a proxy stands in for the edge: it shuts both
//! directions down with a FIN, keeping the sockets open so nothing is reset.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::io::AsyncWriteExt;
    use citadel_io::tokio::net::{TcpListener, TcpStream};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// Far below the 15-minute keep-alive sleep that held the session, and long
    /// enough for a loaded runner to finish a handshake.
    const MUST_RECONNECT_WITHIN: Duration = Duration::from_secs(30);

    /// Relays TCP to `upstream`; `close_all` sends a FIN both ways on every relayed link.
    struct FinProxy {
        addr: SocketAddr,
        close: Arc<citadel_io::tokio::sync::Notify>,
    }

    impl FinProxy {
        async fn start(upstream: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let close = Arc::new(citadel_io::tokio::sync::Notify::new());
            let close_for_links = close.clone();
            citadel_io::tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let server = TcpStream::connect(upstream).await.unwrap();
                    citadel_io::tokio::spawn(relay(client, server, close_for_links.clone()));
                }
            });
            Self { addr, close }
        }

        fn close_all(&self) {
            self.close.notify_waiters();
        }
    }

    async fn relay(
        client: TcpStream,
        server: TcpStream,
        close: Arc<citadel_io::tokio::sync::Notify>,
    ) {
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let closing = close.notified();
        citadel_io::tokio::select! {
            _ = citadel_io::tokio::io::copy(&mut client_read, &mut server_write) => return,
            _ = citadel_io::tokio::io::copy(&mut server_read, &mut client_write) => return,
            _ = closing => {}
        }
        // FIN, not RST: shut the write halves down and keep every half alive, so
        // no socket is dropped with unread data (which would reset it).
        let _ = server_write.shutdown().await;
        let _ = client_write.shutdown().await;
        std::mem::forget((client_read, client_write, server_read, server_write));
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_cleanly_closed_link_frees_its_session() {
        citadel_logging::setup_log();

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            |_connection| async move { Ok(()) },
            |_| {},
        );
        let proxy = Arc::new(FinProxy::start(server_addr).await);
        let proxy_addr = proxy.addr;

        let username = format!("fin_{}", &Uuid::new_v4().to_string()[..8]);
        let password = "password123";

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                remote
                    .register_with_defaults(
                        proxy_addr,
                        username.as_str(),
                        username.as_str(),
                        password,
                    )
                    .await?;
                let first = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                let cid = first.cid;
                // Let the keep-alive exchange start, so a handler is in flight on the server.
                citadel_io::tokio::time::sleep(Duration::from_secs(3)).await;

                proxy.close_all();
                let deadline = citadel_io::tokio::time::Instant::now() + MUST_RECONNECT_WITHIN;
                loop {
                    citadel_io::tokio::time::sleep(Duration::from_secs(1)).await;
                    let last_error = match remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await
                    {
                        Ok(again) => {
                            assert_eq!(again.cid, cid, "a reconnect keeps the account's CID");
                            return again.shutdown_kernel().await;
                        }
                        Err(err) => err.into_string(),
                    };
                    if citadel_io::tokio::time::Instant::now() >= deadline {
                        return Err(NetworkError::msg(format!(
                            "still refused {MUST_RECONNECT_WITHIN:?} after a clean close: {last_error}"
                        )));
                    }
                }
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let result = citadel_io::tokio::time::timeout(Duration::from_secs(120), async move {
            citadel_io::tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = client => res,
            }
        })
        .await
        .expect("the test itself timed out");
        assert!(result.is_ok(), "{result:?}");
    }
}
