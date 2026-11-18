//! An incoming QUIC connection gets its handshake and first bidirectional stream within the
//! deadline the listener passes, or it is dropped and closed. Neither the endpoint's keep-alive
//! nor quinn's idle timeout decides how long an accept can last.
#![cfg(not(target_family = "wasm"))]

use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_wire::quic::{accept_biconn, QuicClient, QuicServer, SELF_SIGNED_DOMAIN};
use std::time::Duration;

/// A short deadline, so the test runs in real time without waiting out the production one.
const TEST_ACCEPT_DEADLINE: Duration = Duration::from_millis(500);

/// The bound on the whole test. Past quinn's 30 s idle timeout is not needed: the server's own
/// keep-alive keeps a stream-less connection alive, so only the deadline can end the accept.
const TEST_BOUND: Duration = Duration::from_secs(10);

#[tokio::test]
async fn a_connection_that_never_opens_a_stream_is_closed_at_the_accept_deadline() {
    let server =
        QuicServer::new_self_signed(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    let server_endpoint = server.endpoint.clone();

    let accept = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.expect("endpoint closed");
        accept_biconn(incoming, TEST_ACCEPT_DEADLINE)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    });

    // Handshake only: the client never calls open_bi.
    let client = QuicClient::new_no_verify(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let conn = tokio::time::timeout(
        TEST_BOUND,
        client.endpoint.connect(addr, SELF_SIGNED_DOMAIN).unwrap(),
    )
    .await
    .expect("handshake never finished")
    .expect("handshake failed");

    let outcome = tokio::time::timeout(TEST_BOUND, accept)
        .await
        .expect("the accept outlived its deadline")
        .unwrap();
    let err = outcome.expect_err("a connection with no stream was accepted");
    assert!(err.contains("first stream"), "{err}");

    let reason = tokio::time::timeout(TEST_BOUND, conn.closed())
        .await
        .expect("the server kept the expired connection open");
    println!("client saw the connection close: {reason:?}");
}
