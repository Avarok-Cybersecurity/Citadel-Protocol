#![cfg(not(target_family = "wasm"))]
//! A handshake that stops making progress is ended by the node's limit for an unconnected
//! session, and the caller hears why instead of waiting forever.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::tokio;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::{TcpListener, TcpStream};
    use citadel_io::ErrorCode;
    use citadel_sdk::prelude::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Relays every byte the client sends, but of the server's only its first read (the
    /// connection's first packet); after that the client hears nothing, and nothing is closed.
    async fn first_packet_only(upstream: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(upstream).await.unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let mut first = vec![0u8; 64 * 1024];
            let n = server_read.read(&mut first).await.unwrap();
            client_write.write_all(&first[..n]).await.unwrap();
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
            std::future::pending::<()>().await;
            drop((client_write, server_read));
        }));
        addr
    }

    /// Control: drop the login-deadline checks in `CitadelSession::execute` and the
    /// registration is misreported or waits until the deadline below instead.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_stalled_registration_fails_with_the_reason() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("stall");
        run(server, move |remote, _| async move {
            let stalled = first_packet_only(addr).await;
            let register = remote.register_with_defaults(
                stalled,
                user.as_str(),
                user.as_str(),
                PASSWORD,
                CertVerification::SelfSignedAccepted,
            );
            // Well past the node's limit, so only a hang reaches it.
            let answer = tokio::time::timeout(Duration::from_secs(120), register).await;
            let Err(err) = answer.expect("the stalled registration never answered") else {
                panic!("a stalled registration succeeded");
            };
            // A registration past the login deadline is the same condition as a login past it
            // (`a_late_credentialed_login_is_a_timeout`), reported the same way.
            assert_eq!(err.code, ErrorCode::Timeout, "misreported as: {err:?}");
            assert!(err.to_string().contains("login deadline"), "{err}");
            remote.shutdown().await
        })
        .await;
    }
}
