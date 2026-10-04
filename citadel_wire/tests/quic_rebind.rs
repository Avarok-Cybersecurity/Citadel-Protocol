//! A client QUIC endpoint moved to a fresh socket keeps its connection: same `Connection`, no
//! second handshake, and the server (which allows migration) follows the client to its new port.
//!
//! Run: `cargo nextest run -p citadel_wire --test quic_rebind`
#![cfg(not(target_family = "wasm"))]

use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_wire::exports::{Connection, RecvStream, SendStream};
use citadel_wire::quic::{QuicClient, QuicEndpointConnector, QuicEndpointListener, QuicServer};
use citadel_wire::quic_rebind::LiveQuicEndpoints;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Bounds every wait on the peer; nothing here should take more than a few milliseconds.
const STEP: Duration = Duration::from_secs(10);

struct Server {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    conn: tokio::sync::oneshot::Receiver<Connection>,
}

/// A server that echoes every 1-byte message on the first stream of each connection it accepts.
async fn echo_server() -> Server {
    let mut node =
        QuicServer::new_self_signed(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let addr = node.endpoint.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (conn_tx, conn) = tokio::sync::oneshot::channel();
    let count = accepted.clone();
    drop(tokio::spawn(async move {
        let mut conn_tx = Some(conn_tx);
        while let Ok((conn, sink, stream)) = node.next_connection().await {
            let _ = count.fetch_add(1, Ordering::SeqCst);
            if let Some(tx) = conn_tx.take() {
                let _ = tx.send(conn.clone());
            }
            drop(tokio::spawn(echo(sink, stream)));
        }
    }));
    Server {
        addr,
        accepted,
        conn,
    }
}

async fn echo(mut sink: SendStream, mut stream: RecvStream) {
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        if sink.write_all(&byte).await.is_err() {
            return;
        }
    }
}

async fn round_trip(sink: &mut SendStream, stream: &mut RecvStream, byte: u8) {
    sink.write_all(&[byte]).await.unwrap();
    let mut back = [0u8; 1];
    tokio::time::timeout(STEP, stream.read_exact(&mut back))
        .await
        .expect("the echo did not come back over the path")
        .unwrap();
    assert_eq!(back, [byte]);
}

#[tokio::test]
async fn a_rebound_client_keeps_its_connection_and_the_server_follows_it() {
    let mut server = echo_server().await;
    let client = QuicClient::new_no_verify(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let old_local = client.endpoint.local_addr().unwrap();
    let (conn, mut sink, mut stream) = client
        .connect_biconn(server.addr, citadel_wire::quic::SELF_SIGNED_DOMAIN)
        .await
        .unwrap();
    let server_conn = tokio::time::timeout(STEP, &mut server.conn)
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut sink, &mut stream, 1).await;
    assert_eq!(server_conn.remote_address(), old_local);

    let live = LiveQuicEndpoints::new();
    live.track(client.endpoint.clone());
    let id_before = conn.stable_id();
    let report = live.rebind_all();

    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(report.rebound.len(), 1, "{report:?}");
    let moved = &report.rebound[0];
    assert_eq!(moved.from, old_local);
    assert_ne!(moved.to.port(), old_local.port());
    assert_eq!(client.endpoint.local_addr().unwrap(), moved.to);

    round_trip(&mut sink, &mut stream, 2).await;
    assert_eq!(conn.stable_id(), id_before);
    assert!(conn.close_reason().is_none());
    assert_eq!(
        server_conn.remote_address().port(),
        moved.to.port(),
        "the server must see the client at its new port"
    );
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        1,
        "no second handshake"
    );
}

#[tokio::test]
async fn an_endpoint_whose_connections_closed_is_not_rebound() {
    let server = echo_server().await;
    let client = QuicClient::new_no_verify(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let (conn, _sink, _stream) = client
        .connect_biconn(server.addr, citadel_wire::quic::SELF_SIGNED_DOMAIN)
        .await
        .unwrap();
    let live = LiveQuicEndpoints::new();
    live.track(client.endpoint.clone());
    assert_eq!(live.len(), 1);

    conn.close(0u32.into(), b"done");
    tokio::time::timeout(STEP, client.endpoint.wait_idle())
        .await
        .unwrap();

    assert_eq!(live.len(), 0);
    let report = live.rebind_all();
    assert!(
        report.rebound.is_empty() && report.failed.is_empty(),
        "{report:?}"
    );
}
