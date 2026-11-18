//! TCP and UDP ports are allocated separately, so the UDP twin of a TCP socket's port can be
//! held by an unrelated socket. These hold it on purpose, which is what full-suite load did by
//! chance to `connections::test_many_proto_conns`.
use super::{client_quic_socket, server_socket_pair};
use citadel_io::tokio;
use citadel_wire::socket_helpers::is_ipv6_enabled;
use std::net::{SocketAddr, UdpSocket};

fn loopbacks() -> Vec<SocketAddr> {
    let mut addrs = vec!["127.0.0.1:0".parse().unwrap()];
    if is_ipv6_enabled() {
        addrs.push("[::1]:0".parse().unwrap());
    }
    addrs
}

/// An unrelated UDP socket holding a port that TCP has free on `ip`.
fn held_udp_port(any: SocketAddr) -> (UdpSocket, SocketAddr) {
    let holder = UdpSocket::bind(any).unwrap();
    let held = holder.local_addr().unwrap();
    (holder, held)
}

#[citadel_io::tokio::test]
async fn a_client_whose_tcp_port_is_held_for_udp_still_gets_a_quic_socket() {
    for any in loopbacks() {
        let (_holder, held) = held_udp_port(any);
        let socket = client_quic_socket(held).unwrap_or_else(|err| {
            panic!("{held}: no QUIC socket while its UDP twin is held: {err}")
        });
        let bound = socket.local_addr().unwrap();
        assert_eq!(bound.ip(), held.ip());
        assert_ne!(bound.port(), held.port());
    }
}

#[citadel_io::tokio::test]
async fn a_client_whose_tcp_port_is_free_for_udp_keeps_it() {
    for any in loopbacks() {
        let free = held_udp_port(any).1;
        let socket = client_quic_socket(free).unwrap();
        assert_eq!(socket.local_addr().unwrap(), free);
    }
}

#[citadel_io::tokio::test]
async fn a_server_asked_for_a_held_port_reports_it() {
    for any in loopbacks() {
        let (_holder, held) = held_udp_port(any);
        let err = server_socket_pair(held).expect_err("bound a QUIC socket on a held UDP port");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{held}: {err}");
    }
}

#[citadel_io::tokio::test]
async fn a_server_asked_for_any_port_gets_one_free_in_both() {
    for any in loopbacks() {
        let (tcp, udp) = server_socket_pair(any).unwrap();
        assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    }
}
