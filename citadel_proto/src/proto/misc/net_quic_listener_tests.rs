//! One incoming QUIC connection that fails must not end the listener.
//!
//! During hole punching a peer routinely abandons a QUIC handshake. The
//! listener has to drop that connection and keep accepting: the server's
//! accept loop keeps polling after an error, so a listener that ended on it
//! would be polled again after completion.

use super::GenericNetworkListener;
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_wire::exports::{Connection, RecvStream, SendStream};
use citadel_wire::quic::{
    generate_self_signed_cert, QuicClient, QuicEndpointConnector, QuicNode, QuicServer,
    SELF_SIGNED_DOMAIN,
};
use citadel_wire::tls::create_rustls_client_config;
use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

async fn quic_listener() -> (GenericNetworkListener, SocketAddr) {
    let node = QuicServer::new_self_signed(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let addr = node.endpoint.local_addr().unwrap();
    (
        GenericNetworkListener::from_quic_node(node, true).unwrap(),
        addr,
    )
}

async fn good_client() -> (QuicNode, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (QuicClient::new_no_verify(socket).unwrap(), addr)
}

/// Polls the listener the way the server's accept loop does: an error is
/// logged and the loop polls again.
async fn next_accepted(listener: &mut GenericNetworkListener) -> SocketAddr {
    loop {
        match listener.next().await {
            Some(Ok((_stream, addr))) => return addr,
            Some(Err(err)) => log::warn!(target: "citadel", "listener error: {err}"),
            None => panic!("the QUIC listener ended"),
        }
    }
}

/// Connects a good client and returns its address, with the connection it
/// must keep open until the listener has taken it.
async fn then_connect_a_good_client(listen_addr: SocketAddr) -> (SocketAddr, OpenConnection) {
    let (client, addr) = good_client().await;
    let (conn, mut tx, rx) = client
        .connect_biconn(listen_addr, SELF_SIGNED_DOMAIN)
        .await
        .unwrap();
    tx.write_all(b"hello").await.unwrap();
    (addr, (client, conn, tx, rx))
}

type OpenConnection = (QuicNode, Connection, SendStream, RecvStream);

async fn assert_listener_survives<F: std::future::Future<Output = ()>>(
    bad: impl FnOnce(SocketAddr) -> F,
) {
    let (mut listener, listen_addr) = quic_listener().await;

    let clients = async {
        bad(listen_addr).await;
        then_connect_a_good_client(listen_addr).await
    };

    let (accepted, (good, _keep_open)) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(next_accepted(&mut listener), clients)
    })
    .await
    .expect("the good client was never accepted after the failed one");
    assert_eq!(accepted, good);
}

#[tokio::test]
async fn a_rejected_handshake_does_not_end_the_quic_listener() {
    assert_listener_survives(|listen_addr| async move {
        // Trusts only an unrelated certificate, so it aborts the handshake
        // when the listener presents its own.
        let (unrelated_cert, _key) = generate_self_signed_cert().unwrap();
        let config = create_rustls_client_config(&[unrelated_cert]).unwrap();
        let client = QuicClient::new_with_rustls_config(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            Arc::new(config),
        )
        .unwrap();
        let res = client.connect_biconn(listen_addr, SELF_SIGNED_DOMAIN).await;
        assert!(
            res.is_err(),
            "the untrusting client completed its handshake"
        );
        // the server learns of the abort from the client's close
        client.endpoint.wait_idle().await;
    })
    .await;
}

#[tokio::test]
async fn a_connection_closed_before_its_stream_does_not_end_the_quic_listener() {
    assert_listener_survives(|listen_addr| async move {
        let (client, _) = good_client().await;
        let conn = client
            .endpoint
            .connect(listen_addr, SELF_SIGNED_DOMAIN)
            .unwrap()
            .await
            .unwrap();
        conn.close(0u32.into(), b"abandoned");
        client.endpoint.wait_idle().await;
    })
    .await;
}

#[tokio::test]
async fn a_closed_quic_listener_ends_instead_of_being_polled_after_completion() {
    let node = QuicServer::new_self_signed(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let endpoint = node.endpoint.clone();
    let mut listener = GenericNetworkListener::from_quic_node(node, true).unwrap();
    endpoint.close(0u32.into(), b"closed");

    // Polled the way the server's accept loop polls it: past every error.
    let errors = tokio::time::timeout(Duration::from_secs(10), async {
        let mut errors = 0;
        while let Some(item) = listener.next().await {
            assert!(item.is_err(), "a closed listener accepted a connection");
            errors += 1;
        }
        errors
    })
    .await
    .expect("the closed listener never ended");
    assert!(errors >= 1, "the listener ended without reporting why");
}
