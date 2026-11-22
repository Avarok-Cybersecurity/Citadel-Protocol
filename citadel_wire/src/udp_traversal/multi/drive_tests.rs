//! `drive` end to end, for outcomes that need no race to reach.

use super::DualStackUdpHolePuncher;
use crate::nat_identification::NatType;
use crate::socket_helpers::get_udp_socket;
use crate::udp_traversal::attempt_commit::AttemptCommit;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use crate::udp_traversal::linear::encrypted_config_container::identity_for_tests;
use citadel_io::tokio;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

/// Method3 gives up after 3 s. Well inside one attempt's 20 s budget.
const PROMPT: Duration = Duration::from_secs(10);

fn aimed_at_silence(
    app: NetworkEndpoint,
    silent_peer: &std::net::UdpSocket,
) -> DualStackUdpHolePuncher {
    let config = HolePunchConfig::new(
        &NatType::default(),
        &[silent_peer.local_addr().unwrap()],
        &[],
        vec![get_udp_socket("127.0.0.1:0").unwrap()],
    )
    .unwrap();
    DualStackUdpHolePuncher::new(
        app.node_type(),
        identity_for_tests(),
        config,
        app,
        AttemptCommit::new(),
    )
    .unwrap()
}

/// When every puncher on both sides has failed, no winner can appear. Both
/// sides used to know that and still wait for the attempt's timeout, so the
/// retry started 20 s late.
#[tokio::test]
async fn a_mutual_failure_ends_the_attempt_promptly() {
    let (a, b) = create_streams_with_addrs().await;
    let silent_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    let (res_a, res_b) = tokio::time::timeout(PROMPT, async {
        tokio::join!(
            aimed_at_silence(a, &silent_a),
            aimed_at_silence(b, &silent_b)
        )
    })
    .await
    .expect("both sides had failed, but the attempt waited for its timeout");

    assert!(res_a.is_err() && res_b.is_err());
}

/// Two sockets a side on one host, every one reaching every other: the topology of two
/// sessions in one agent. Whatever pair wins, both sides must hold its two halves -- each
/// side aimed at the socket the other kept. A loser that kept a different local socket left
/// the winner's QUIC dial unanswered, and the attempt failed with both punches "finished".
#[tokio::test]
async fn both_sides_hold_the_same_pair_when_every_socket_reaches_every_other() {
    for round in 0..20 {
        let (a, b) = create_streams_with_addrs().await;
        let a_sockets = vec![
            get_udp_socket("127.0.0.1:0").unwrap(),
            get_udp_socket("127.0.0.1:0").unwrap(),
        ];
        let b_sockets = vec![
            get_udp_socket("127.0.0.1:0").unwrap(),
            get_udp_socket("127.0.0.1:0").unwrap(),
        ];
        let addrs = |s: &Vec<citadel_io::tokio::net::UdpSocket>| {
            s.iter()
                .map(|s| s.local_addr().unwrap())
                .collect::<Vec<_>>()
        };
        let (a_at, b_at) = (addrs(&a_sockets), addrs(&b_sockets));
        let puncher = |app: NetworkEndpoint, peer: &[std::net::SocketAddr], mine| {
            let config = HolePunchConfig::new(&NatType::default(), peer, &[], mine).unwrap();
            DualStackUdpHolePuncher::new(
                app.node_type(),
                identity_for_tests(),
                config,
                app,
                AttemptCommit::new(),
            )
            .unwrap()
        };
        let (res_a, res_b) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(puncher(a, &b_at, a_sockets), puncher(b, &a_at, b_sockets))
        })
        .await
        .expect("the punch did not finish");
        let (sock_a, sock_b) = (res_a.unwrap(), res_b.unwrap());
        let (a_local, b_local) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        assert_eq!(
            (
                sock_a.addr.send_address.port(),
                sock_b.addr.send_address.port()
            ),
            (b_local.port(), a_local.port()),
            "round {round}: A kept {a_local} aimed at {}, B kept {b_local} aimed at {}",
            sock_a.addr.send_address,
            sock_b.addr.send_address,
        );
    }
}
