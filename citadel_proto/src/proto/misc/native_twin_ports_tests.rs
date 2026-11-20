//! TCP and UDP ports are allocated separately, so the UDP twin of a TCP socket's port can be
//! held by an unrelated socket. These hold it on purpose, which is what full-suite load did by
//! chance to `connections::test_many_proto_conns`.
use super::{client_quic_socket, server_socket_pair, twin_unavailable};
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
        // Windows answers WSAEACCES (PermissionDenied), not WSAEADDRINUSE, when the holder's
        // port is one it treats as exclusive; the server reports either as the same refusal.
        assert!(twin_unavailable(&err), "{held}: {err} ({:?})", err.kind());
    }
}

#[citadel_io::tokio::test]
async fn a_server_asked_for_any_port_gets_one_free_in_both() {
    for any in loopbacks() {
        let (tcp, udp) = server_socket_pair(any).unwrap();
        assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    }
}

/// What GitHub's Windows runners do: the TCP allocator hands out ports in sequence, and a run of
/// them is reserved for UDP (WSAEACCES). Every draw TCP makes lands in the run.
mod a_reserved_run {
    use super::super::{beside_signalling, draw_pair};
    use std::cell::Cell;
    use std::io;
    use std::net::SocketAddr;

    const RESERVED_FOR_UDP: std::ops::Range<u16> = 50_000..50_100;
    const UDP_PICKS: u16 = 60_000;

    fn any() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn denied() -> io::Error {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }

    /// A TCP allocator walking up through the reserved run, and a UDP allocator that skips it.
    type Bound = io::Result<(u16, SocketAddr)>;

    fn binders() -> (impl Fn(SocketAddr) -> Bound, impl Fn(SocketAddr) -> Bound) {
        let next_tcp = Cell::new(RESERVED_FOR_UDP.start);
        let tcp = move |at: SocketAddr| {
            let port = if at.port() == 0 {
                next_tcp.replace(next_tcp.get() + 1)
            } else {
                at.port()
            };
            Ok((port, SocketAddr::new(at.ip(), port)))
        };
        let udp = |at: SocketAddr| match at.port() {
            0 => Ok((UDP_PICKS, SocketAddr::new(at.ip(), UDP_PICKS))),
            port if RESERVED_FOR_UDP.contains(&port) => Err(denied()),
            port => Ok((port, at)),
        };
        (tcp, udp)
    }

    #[test]
    fn a_server_asked_for_any_port_finds_one_free_in_both() {
        let (tcp, udp) = binders();
        let (tcp, udp) = draw_pair(any(), tcp, udp).expect("no pair outside the reserved run");
        assert_eq!(tcp, udp);
        assert!(!RESERVED_FOR_UDP.contains(&udp));
    }

    #[test]
    fn a_server_asked_for_a_reserved_port_reports_it() {
        let (tcp, udp) = binders();
        let reserved = SocketAddr::new(any().ip(), RESERVED_FOR_UDP.start);
        let err = draw_pair(reserved, tcp, udp).expect_err("bound a reserved UDP port");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_client_whose_tcp_port_is_reserved_for_udp_still_gets_a_quic_socket() {
        let (_, udp) = binders();
        let signalling = SocketAddr::new(any().ip(), RESERVED_FOR_UDP.start);
        let (port, _) = beside_signalling(signalling, udp).expect("no QUIC socket");
        assert_eq!(port, UDP_PICKS);
    }

    #[test]
    fn a_failure_the_port_cannot_cure_is_not_drawn_around() {
        let unreachable =
            |_: SocketAddr| -> Bound { Err(io::Error::from(io::ErrorKind::AddrNotAvailable)) };
        let tried = Cell::new(0);
        let tcp = |at: SocketAddr| {
            tried.set(tried.get() + 1);
            Ok((1, SocketAddr::new(at.ip(), 1)))
        };
        let err = draw_pair(any(), tcp, unreachable).expect_err("bound an unreachable address");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(tried.get(), 1);
    }
}
