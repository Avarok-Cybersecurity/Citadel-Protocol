//! `NatType::get_reflexive_addr` against local STUN responders and silent servers over
//! loopback, with no real network, so the observe-the-real-mapping path is covered even
//! though the hole-punch driver gates it off under localhost-testing.

use crate::nat_identification::{NatType, STUN_PROBE_WINDOW};
use crate::stun_servers::StunServers;
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

/// The external address the fake STUN server reports back.
fn mapped() -> SocketAddr {
    SocketAddr::from_str("203.0.113.9:51234").unwrap()
}

/// A fake STUN server that answers one request: it echoes the request's transaction id in a
/// BINDING_SUCCESS carrying an XOR-MAPPED-ADDRESS of `mapped`. `build()` clears attributes but
/// preserves `transaction_id`, and `XorMappedAddress` encodes against it, so the client can
/// match and decode.
async fn one_shot_responder(mapped: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use stun::message::{Message, BINDING_SUCCESS};
    use stun::xoraddr::XorMappedAddress;

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let task = tokio::task::spawn(async move {
        let mut buf = [0u8; 256];
        let (len, from) = server.recv_from(&mut buf).await.unwrap();
        let mut request = Message::new();
        request.raw = buf[..len].to_vec();
        request.decode().unwrap();

        let mut response = Message::new();
        response.transaction_id = request.transaction_id;
        response
            .build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: mapped.ip(),
                    port: mapped.port(),
                }),
            ])
            .unwrap();
        server.send_to(&response.raw, from).await.unwrap();
    });
    (server_addr, task)
}

/// Bound sockets that swallow every request, kept alive by the caller so that requests are
/// neither answered nor refused.
fn silent_servers(count: usize) -> Vec<std::net::UdpSocket> {
    (0..count)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect()
}

#[tokio::test]
async fn get_reflexive_addr_parses_local_stun_response() {
    let (server_addr, server_task) = one_shot_responder(mapped()).await;
    let silent = silent_servers(2);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let servers = StunServers::new(
        std::iter::once(server_addr)
            .chain(silent.iter().map(|s| s.local_addr().unwrap()))
            .map(|addr| addr.to_string()),
    )
    .unwrap();
    let observed = NatType::get_reflexive_addr(&client, &servers).await;
    server_task.await.unwrap();

    assert_eq!(
        observed,
        Some(mapped()),
        "reflexive addr must match the STUN-reported mapping"
    );
}

/// Silent servers listed before the one that answers cost nothing: every server is asked at
/// once, so the answer arrives within one probe window. Asking them in turn spent a full
/// window on each silent server first, which a hole-punch attempt pays out of its own budget.
#[tokio::test]
async fn silent_servers_ahead_of_an_answering_one_cost_no_window() {
    let silent = silent_servers(2);
    let (server_addr, server_task) = one_shot_responder(mapped()).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let servers = StunServers::new(
        silent
            .iter()
            .map(|s| s.local_addr().unwrap())
            .chain(std::iter::once(server_addr))
            .map(|addr| addr.to_string()),
    )
    .unwrap();

    let started = Instant::now();
    let observed = NatType::get_reflexive_addr(&client, &servers).await;
    let elapsed = started.elapsed();
    server_task.await.unwrap();

    assert_eq!(observed, Some(mapped()));
    assert!(
        elapsed < STUN_PROBE_WINDOW,
        "the answer took {elapsed:?}, so the silent servers were waited out first"
    );
}

/// With no server answering, the probe gives up after one window, not one per server.
#[tokio::test]
async fn an_unanswered_probe_takes_one_window() {
    let silent = silent_servers(3);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let servers =
        StunServers::new(silent.iter().map(|s| s.local_addr().unwrap().to_string())).unwrap();

    let started = Instant::now();
    let observed = NatType::get_reflexive_addr(&client, &servers).await;
    let elapsed = started.elapsed();

    assert_eq!(observed, None);
    assert!(
        elapsed < STUN_PROBE_WINDOW * 2,
        "an unanswered probe took {elapsed:?}: a window per silent server"
    );
}

/// An IPv6 probe socket is skipped (cannot reach the IPv4 STUN servers) and returns None
/// without any network I/O.
#[tokio::test]
async fn get_reflexive_addr_skips_ipv6_socket() {
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let observed =
        NatType::get_reflexive_addr(&socket, &crate::stun_servers::unanswered_loopback()).await;
    assert_eq!(observed, None);
}
