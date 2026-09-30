//! A hole punch on a network where NAT identification cannot succeed.
//!
//! On a LAN, or behind a firewall with no reachable STUN server, `NatType::identify`
//! fails. That must not abort the punch: the peers can still reach each other at their
//! local addresses, so each side must describe itself as *unidentified* (no translation
//! model, but its real internal IP) and punch towards the local candidates.
//!
//! The STUN "servers" here are bound local UDP sockets that never answer, so every
//! identification and every reflexive probe fails the way it does when no STUN server is
//! reachable. Nothing else differs from a healthy run.
//!
//! Run: `cargo nextest run -p citadel_wire --test hole_punch_without_nat_identification`
//! (without the `localhost-testing` feature, which short-circuits identification).
#![cfg(not(feature = "localhost-testing"))]

use citadel_io::tokio;
use citadel_wire::nat_identification::NatType;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use citadel_wire::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;

/// Three bound sockets that swallow every request. Kept alive by the caller so that the
/// requests are neither answered nor refused.
fn silent_stun_servers() -> (Vec<std::net::UdpSocket>, Vec<String>) {
    let sockets = (0..3)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addrs = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().to_string())
        .collect();
    (sockets, addrs)
}

fn container(stun_servers: Vec<String>) -> HolePunchConfigContainer {
    HolePunchConfigContainer::new(
        |plaintext| plaintext.into(),
        |ciphertext| Some(ciphertext.into()),
        Some(stun_servers),
    )
}

#[tokio::test]
async fn a_failed_nat_identification_still_punches_using_local_candidates() {
    citadel_logging::setup_log();
    let (_silent, servers) = silent_stun_servers();

    assert!(
        NatType::identify(Some(servers.clone())).await.is_err(),
        "precondition: with no STUN server answering, identification must fail"
    );

    let (server_stream, client_stream) = create_streams_with_addrs_and_lag(0).await;
    let (server_servers, client_servers) = (servers.clone(), servers);
    let server = tokio::task::spawn(async move {
        server_stream
            .begin_udp_hole_punch(container(server_servers))
            .await
            .map_err(|e| e.to_string())
    });
    let client = tokio::task::spawn(async move {
        client_stream
            .begin_udp_hole_punch(container(client_servers))
            .await
            .map_err(|e| e.to_string())
    });
    let (server, client) = tokio::join!(server, client);
    let server = server
        .unwrap()
        .expect("server: an unidentified NAT aborted the punch");
    let client = client
        .unwrap()
        .expect("client: an unidentified NAT aborted the punch");

    // "An existing connection was forcibly closed by the remote host" on Windows, as in
    // `udp_hole_puncher::tests::test_dual_hole_puncher`.
    #[cfg(not(target_os = "windows"))]
    {
        let buf = &mut [0u8; 4096];
        server
            .send_to(b"server to client" as &[u8], server.addr.send_address)
            .await
            .unwrap();
        let (len, _) = client.recv_from(buf).await.unwrap();
        assert_eq!(&buf[..len], b"server to client");
        client
            .send_to(b"client to server" as &[u8], client.addr.send_address)
            .await
            .unwrap();
        let (len, _) = server.recv_from(buf).await.unwrap();
        assert_eq!(&buf[..len], b"client to server");
    }
}
