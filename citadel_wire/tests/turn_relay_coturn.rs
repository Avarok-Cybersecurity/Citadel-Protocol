//! TURN client against a real coturn over UDP, TCP and TLS: allocation, permissions, channels,
//! refresh, credential rejection, and QUIC running over the relayed socket.
//!
//! Needs coturn's `turnserver` on PATH (or `CITADEL_TURNSERVER_BIN`); ignored by default so CI
//! without coturn stays green. Run: `cargo nextest run -p citadel_wire --test turn_relay_coturn
//! --run-ignored all`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_wire::quic::{
    relayed_client_config, QuicEndpointConnector, QuicEndpointListener, QuicServer,
    RELAYED_QUIC_MTU, SELF_SIGNED_DOMAIN,
};
use citadel_wire::udp_traversal::turn_relay::{
    TurnAllocation, TurnRelaySocket, TurnServerCredential, TurnTransport,
};
use common::coturn::{Coturn, PASSWORD, USER};
use rstest::rstest;

const STEP: Duration = Duration::from_secs(5);

fn credential(server: &Coturn, transport: &str, password: &str) -> TurnServerCredential {
    TurnServerCredential::new(&server.url(transport), USER, password, None).unwrap()
}

async fn allocate(server: &Coturn, transport: &str) -> TurnAllocation {
    TurnAllocation::allocate(
        &credential(server, transport, PASSWORD),
        Some(server.tls_config()),
    )
    .await
    .unwrap_or_else(|e| panic!("allocate over {transport}: {e}\n{}", server.log()))
}

async fn recv_relayed(alloc: &TurnAllocation) -> (SocketAddr, Vec<u8>) {
    tokio::time::timeout(STEP, alloc.recv_from())
        .await
        .expect("relayed datagram did not arrive")
        .unwrap()
}

#[rstest]
#[case("udp", TurnTransport::Udp)]
#[case("tcp", TurnTransport::Tcp)]
#[case("tls", TurnTransport::Tls)]
#[ignore = "needs coturn (turnserver) on PATH"]
#[tokio::test]
async fn allocate_permit_bind_and_relay(#[case] transport: &str, #[case] expect: TurnTransport) {
    citadel_logging::setup_log();
    let server = Coturn::start(Duration::from_secs(600));
    let alloc = allocate(&server, transport).await;
    assert_eq!(alloc.transport(), expect);
    assert_eq!(
        alloc.relayed_addr().ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(Some(alloc.mapped_addr()), alloc.local_addr());

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    // Before any permission the server drops the peer's datagrams (RFC 8656 §9).
    peer.send_to(b"unpermitted", alloc.relayed_addr())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(700), alloc.recv_from())
            .await
            .is_err(),
        "a datagram from an unpermitted peer was relayed"
    );
    assert!(
        alloc.send_to(peer_addr, b"x").is_err(),
        "sent without permission"
    );

    // Permission installed: Data indication inbound, Send indication outbound.
    alloc.create_permissions(&[peer_addr.ip()]).await.unwrap();
    peer.send_to(b"via-data-indication", alloc.relayed_addr())
        .await
        .unwrap();
    assert_eq!(
        recv_relayed(&alloc).await,
        (peer_addr, b"via-data-indication".to_vec())
    );
    alloc.send_to(peer_addr, b"via-send-indication").unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(STEP, peer.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (from, &buf[..n]),
        (alloc.relayed_addr(), &b"via-send-indication"[..])
    );

    // Channel bound: ChannelData both ways, including a full relayed-MTU packet (5 bytes of
    // payload also exercises the TCP/TLS 4-byte padding).
    let channel = alloc.bind_channel(peer_addr).await.unwrap();
    assert!((0x4000..=0x4FFF).contains(&channel));
    assert_eq!(alloc.bind_channel(peer_addr).await.unwrap(), channel);
    for payload in [vec![7u8; 5], vec![9u8; RELAYED_QUIC_MTU as usize]] {
        alloc.send_to(peer_addr, &payload).unwrap();
        let (n, from) = tokio::time::timeout(STEP, peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((from, &buf[..n]), (alloc.relayed_addr(), &payload[..]));
        peer.send_to(&payload, alloc.relayed_addr()).await.unwrap();
        assert_eq!(recv_relayed(&alloc).await, (peer_addr, payload));
    }
}

#[rstest]
#[case("udp")]
#[case("tcp")]
#[case("tls")]
#[ignore = "needs coturn (turnserver) on PATH"]
#[tokio::test]
async fn wrong_credential_is_rejected(#[case] transport: &str) {
    citadel_logging::setup_log();
    let server = Coturn::start(Duration::from_secs(600));
    let err = TurnAllocation::allocate(
        &credential(&server, transport, "not-the-password"),
        Some(server.tls_config()),
    )
    .await
    .expect_err("allocation with a wrong password succeeded");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

#[ignore = "needs coturn (turnserver) on PATH"]
#[tokio::test]
async fn tls_rejects_an_untrusted_certificate() {
    citadel_logging::setup_log();
    let server = Coturn::start(Duration::from_secs(600));
    let native = citadel_wire::tls::load_native_certs_async().await.unwrap();
    let roots = Arc::new(citadel_wire::tls::cert_vec_to_secure_client_config(&native).unwrap());
    let err = TurnAllocation::allocate(&credential(&server, "tls", PASSWORD), Some(roots))
        .await
        .expect_err("self-signed TURN server accepted by the native root store");
    assert!(
        err.to_string().to_lowercase().contains("certificate"),
        "{err}"
    );
}

/// coturn caps the lifetime at 6 s, so without Refresh the allocation (and its channel) would be
/// gone before the second exchange.
#[ignore = "needs coturn (turnserver) on PATH"]
#[tokio::test]
async fn refresh_keeps_a_short_lived_allocation_alive() {
    citadel_logging::setup_log();
    let server = Coturn::start(Duration::from_secs(6));
    let alloc = allocate(&server, "udp").await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    alloc.bind_channel(peer_addr).await.unwrap();
    tokio::time::sleep(Duration::from_secs(14)).await;
    assert!(alloc.is_alive());
    peer.send_to(b"still-here", alloc.relayed_addr())
        .await
        .unwrap();
    assert_eq!(
        recv_relayed(&alloc).await,
        (peer_addr, b"still-here".to_vec())
    );
}

/// quinn over the relayed socket (listener) against a plain UDP dialer: the direct path is never
/// used — the dialer only ever sends to the relayed address.
#[rstest]
#[case("udp")]
#[case("tls")]
#[ignore = "needs coturn (turnserver) on PATH"]
#[tokio::test]
async fn quic_runs_over_the_relay(#[case] transport: &str) {
    citadel_logging::setup_log();
    let server = Coturn::start(Duration::from_secs(600));
    let alloc = Arc::new(allocate(&server, transport).await);
    let dialer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dialer_addr = dialer.local_addr().unwrap();
    alloc.bind_channel(dialer_addr).await.unwrap();
    let relayed = alloc.relayed_addr();

    let mut listener =
        QuicServer::new_self_signed_relayed(Arc::new(TurnRelaySocket::new(alloc))).unwrap();
    let client = citadel_wire::quic::QuicClient::new_no_verify(dialer).unwrap();
    let cfg = relayed_client_config(citadel_wire::quic::insecure::configure_client());

    let accept = async {
        let (conn, _tx, mut rx) = listener.next_connection().await.unwrap();
        let mut buf = [0u8; 5];
        rx.read_exact(&mut buf).await.unwrap();
        let datagram = conn.read_datagram().await.unwrap();
        (conn, buf, datagram)
    };
    let connect = async {
        let (conn, mut tx, _rx) = client
            .connect_biconn_with(relayed, SELF_SIGNED_DOMAIN, Some(cfg))
            .await
            .unwrap();
        tx.write_all(b"hello").await.unwrap();
        let max = conn.max_datagram_size().unwrap();
        conn.send_datagram(vec![0xAB; max].into()).unwrap();
        (conn, max)
    };
    let ((server_conn, hello, datagram), (client_conn, max)) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(accept, connect)
        })
        .await
        .expect("QUIC over TURN did not complete");
    assert_eq!(&hello, b"hello");
    assert_eq!(datagram.len(), max);
    assert_eq!(server_conn.remote_address(), dialer_addr);
    assert_eq!(client_conn.remote_address(), relayed);
    // quinn's ceiling is current_mtu - (1 flags + 8 CID + 4 PN + 16 AEAD tag + 9 DATAGRAM frame
    // bound) = mtu - 38 (1200 -> 1162, as media/config.rs records for direct paths). Equality pins
    // that both ends run at the relayed MTU, i.e. the TURN ChannelData header is accounted for.
    const QUIC_DATAGRAM_OVERHEAD: usize = 38;
    let relayed_ceiling = RELAYED_QUIC_MTU as usize - QUIC_DATAGRAM_OVERHEAD;
    assert_eq!(max, relayed_ceiling, "client datagram ceiling ignores TURN overhead");
    assert_eq!(server_conn.max_datagram_size(), Some(relayed_ceiling));
}
