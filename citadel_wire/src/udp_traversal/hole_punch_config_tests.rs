use super::HolePunchConfig;
use crate::nat_identification::{IpTranslation, NatType, PortTranslation};
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use std::net::SocketAddr;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A peer behind no translation, so the predicted band is its own internal address
/// with or without `localhost-testing` (which replaces only unpredictable models).
fn untranslated_peer() -> NatType {
    NatType {
        ip_translation: IpTranslation::Identity,
        port_translation: PortTranslation::Identity,
        ..NatType::default()
    }
}

/// A local IPv6 + IPv4 socket pair, the shape `driver_inner` binds on an IPv6 host.
async fn dual_stack_sockets() -> Vec<UdpSocket> {
    vec![
        UdpSocket::bind("[::1]:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ]
}

/// Each band set, in socket order, flattened to the addresses that socket pings.
fn candidates_per_socket(config: HolePunchConfig) -> Vec<Vec<SocketAddr>> {
    config.into_iter().collect()
}

/// The owner's agent died on this: an IPv6 host binds two sockets, an IPv4-only peer
/// advertises one internal address, and the count mismatch reached an `assert_eq!`.
#[tokio::test]
async fn fewer_peer_candidates_than_local_sockets_does_not_panic() {
    let peer = [addr("192.168.1.50:40000")];
    let config = HolePunchConfig::new(&NatType::default(), &peer, &[], dual_stack_sockets().await);
    assert!(config.is_ok(), "{config:?}");
}

/// The mismatch must not just stop panicking: the IPv4 socket has to be aimed at the
/// IPv4-only peer, or the pair never punches.
#[tokio::test]
async fn ipv4_only_peer_is_paired_with_the_local_ipv4_socket() {
    let peer_internal = addr("192.168.1.50:40000");
    let peer_reflexive = addr("203.0.113.7:55555");
    let config = HolePunchConfig::new(
        &untranslated_peer(),
        &[peer_internal],
        &[peer_reflexive],
        dual_stack_sockets().await,
    )
    .unwrap();

    let sets = candidates_per_socket(config);
    assert_eq!(sets.len(), 2, "one band set per local socket: {sets:?}");
    let (v6_set, v4_set) = (&sets[0], &sets[1]);
    assert!(v4_set.contains(&peer_internal), "{v4_set:?}");
    assert!(v4_set.contains(&peer_reflexive), "{v4_set:?}");
    assert!(v4_set.iter().all(SocketAddr::is_ipv4), "{v4_set:?}");
    assert!(v6_set.iter().all(SocketAddr::is_ipv6), "{v6_set:?}");
}

/// The other end of the same pair: one local IPv4 socket, two peer candidates.
#[tokio::test]
async fn more_peer_candidates_than_local_sockets_keeps_the_ipv4_one() {
    let peer_mapped = addr("[::ffff:10.0.0.2]:41000");
    let peer_v4 = addr("10.0.0.2:42000");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = HolePunchConfig::new(
        &untranslated_peer(),
        &[peer_mapped, peer_v4],
        &[],
        vec![socket],
    )
    .unwrap();

    let sets = candidates_per_socket(config);
    assert_eq!(sets.len(), 1);
    assert!(sets[0].contains(&peer_v4), "{:?}", sets[0]);
}

#[tokio::test]
async fn no_family_compatible_candidate_is_an_error() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let only_v6 = [addr("[2001:db8::7]:5000")];
    let config = HolePunchConfig::new(&NatType::default(), &[], &only_v6, vec![socket]);
    assert!(config.is_err(), "{config:?}");
}

#[tokio::test]
async fn no_local_sockets_is_an_error() {
    let peer = [addr("192.168.1.50:40000")];
    let config = HolePunchConfig::new(&NatType::default(), &peer, &[], vec![]);
    assert!(config.is_err(), "{config:?}");
}

/// The peer sends its own `NatType`. A delta no `NatType::new` can produce used to
/// size the candidate loops (and overflow `3 * delta`); it must fail the attempt.
#[tokio::test]
async fn out_of_range_peer_nat_delta_is_an_error() {
    for average_delta in [i32::MAX, -1] {
        let nat = NatType {
            port_translation: PortTranslation::DeltaIndependentOffset {
                average_delta,
                last_allocated_external_port: 50000,
            },
            ..untranslated_peer()
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = HolePunchConfig::new(&nat, &[addr("10.0.0.2:4000")], &[], vec![socket]);
        assert!(config.is_err(), "delta {average_delta}: {config:?}");
    }
}

/// An observed server-reflexive (external) address must become a ping candidate even
/// when the predictive NAT model yields nothing — this is the whole point of probing
/// the real socket for endpoint-independent NATs that randomize the external port.
#[tokio::test]
async fn reflexive_addr_becomes_candidate() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_internal = addr("192.168.1.50:40000");
    let reflexive = addr("203.0.113.7:55555");

    // Default NatType is Unpredictable -> predict() returns None (no model bands).
    let nat = NatType::default();
    let config = HolePunchConfig::new(&nat, &[peer_internal], &[reflexive], vec![socket]).unwrap();

    let candidates: Vec<SocketAddr> = config.into_iter().flatten().collect();
    assert!(
        candidates.contains(&reflexive),
        "observed reflexive candidate must be pinged, got: {candidates:?}"
    );
}
