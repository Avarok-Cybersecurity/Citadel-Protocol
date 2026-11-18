use super::{
    check_candidate_pool, MAX_CANDIDATE_ADDRS, MAX_PEER_INTERNAL_ADDRS, MAX_PEER_REFLEXIVE_ADDRS,
};
use crate::nat_identification::{IpTranslation, NatType, PortTranslation, MAX_OCTET_DELTA};
use crate::udp_traversal::hole_punch_config::AddrBand;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use async_ip::IpAddressInfo;
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use std::net::{IpAddr, SocketAddr};

fn addrs(base: &str, count: usize) -> Vec<SocketAddr> {
    let ip: IpAddr = base.parse().unwrap();
    (0..count)
        .map(|i| SocketAddr::new(ip, 40000 + i as u16))
        .collect()
}

fn untranslated_peer() -> NatType {
    NatType {
        ip_translation: IpTranslation::Identity,
        port_translation: PortTranslation::Identity,
        ..NatType::default()
    }
}

/// The widest model `NatType::new` can produce: both translations at the largest delta, with
/// an external IPv6 and a distinct internal IP, so every prediction band is present.
fn widest_honest_peer() -> NatType {
    NatType {
        ip_translation: IpTranslation::DeltaIndependentOffset {
            average_delta: MAX_OCTET_DELTA,
            last_allocated_external_ip: "198.51.100.20".parse().unwrap(),
        },
        port_translation: PortTranslation::DeltaIndependentOffset {
            average_delta: MAX_OCTET_DELTA,
            last_allocated_external_port: 50000,
        },
        ip_info: Some(IpAddressInfo {
            internal_ip: "10.0.0.9".parse().unwrap(),
            external_ipv6: Some("2001:db8::9".parse().unwrap()),
        }),
        ..NatType::default()
    }
}

async fn ipv4_socket() -> Vec<UdpSocket> {
    vec![UdpSocket::bind("127.0.0.1:0").await.unwrap()]
}

fn err_text(config: Result<HolePunchConfig, crate::error::FirewallError>) -> String {
    config.expect_err("the attempt was planned").to_string()
}

#[tokio::test]
async fn more_internal_addresses_than_the_bound_end_the_attempt() {
    let internal = addrs("192.168.1.50", MAX_PEER_INTERNAL_ADDRS + 1);
    let config = HolePunchConfig::new(&untranslated_peer(), &internal, &[], ipv4_socket().await);
    let err = err_text(config);
    assert!(err.contains("internal addresses"), "{err}");
}

#[tokio::test]
async fn more_reflexive_addresses_than_the_bound_end_the_attempt() {
    let internal = addrs("192.168.1.50", 1);
    let reflexive = addrs("203.0.113.7", MAX_PEER_REFLEXIVE_ADDRS + 1);
    let config = HolePunchConfig::new(
        &untranslated_peer(),
        &internal,
        &reflexive,
        ipv4_socket().await,
    );
    let err = err_text(config);
    assert!(err.contains("reflexive addresses"), "{err}");
}

#[tokio::test]
async fn a_broadcast_or_multicast_candidate_ends_the_attempt() {
    for target in ["255.255.255.255", "224.0.0.1"] {
        let config = HolePunchConfig::new(
            &untranslated_peer(),
            &addrs("192.168.1.50", 1),
            &addrs(target, 1),
            ipv4_socket().await,
        );
        let err = err_text(config);
        assert!(err.contains("not a unicast address"), "{target}: {err}");
    }
}

/// A peer's own NAT model can name the target too: a constant translation to a multicast
/// group would aim every predicted band at it.
#[tokio::test]
async fn a_nat_model_naming_a_multicast_group_ends_the_attempt() {
    let peer = NatType {
        ip_translation: IpTranslation::Constant {
            external: "239.1.2.3".parse().unwrap(),
        },
        port_translation: PortTranslation::Identity,
        ..NatType::default()
    };
    let config = HolePunchConfig::new(&peer, &addrs("192.168.1.50", 1), &[], ipv4_socket().await);
    let err = err_text(config);
    assert!(err.contains("not a unicast address"), "{err}");
}

/// The pool bound is derived from the widest honest model, so that model at the list bounds
/// must still plan. If a prediction grows, this fails before any honest peer is refused.
#[tokio::test]
async fn the_widest_honest_candidates_fit_the_pool_bound() {
    let internal = addrs("192.168.1.50", MAX_PEER_INTERNAL_ADDRS);
    let reflexive = addrs("203.0.113.7", MAX_PEER_REFLEXIVE_ADDRS);
    let sockets = vec![
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("[::1]:0").await.unwrap(),
    ];
    let config = HolePunchConfig::new(&widest_honest_peer(), &internal, &reflexive, sockets)
        .expect("the widest honest candidates were refused");
    let planned: usize = config.into_iter().map(|set| set.len()).sum();
    assert!(planned > 0 && planned <= MAX_CANDIDATE_ADDRS, "{planned}");
}

/// The backstop itself: a pool one address past the bound is refused, whatever produced it.
#[test]
fn a_pool_past_the_bound_is_refused() {
    let band = |ports: std::ops::Range<u16>| AddrBand {
        necessary_ip: "192.168.1.50".parse().unwrap(),
        anticipated_ports: ports.collect(),
    };
    let at_bound = [band(1..(MAX_CANDIDATE_ADDRS as u16 + 1))];
    assert!(check_candidate_pool(&at_bound).is_ok());
    let past_bound = [band(1..(MAX_CANDIDATE_ADDRS as u16 + 2))];
    let err = check_candidate_pool(&past_bound).unwrap_err().to_string();
    assert!(err.contains("expand to"), "{err}");
}
