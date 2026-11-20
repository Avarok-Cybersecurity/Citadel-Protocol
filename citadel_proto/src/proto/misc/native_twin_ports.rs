//! The TCP and UDP sockets a QUIC-over-TCP-signalling peer holds on ONE address.
//!
//! A client dials QUIC at the address it reached over TCP, so the server's UDP socket must sit on
//! its TCP listener's port, and a client prefers its QUIC socket on its TCP socket's port. TCP and
//! UDP ports are allocated, held and reserved separately: the port one protocol's allocator hands
//! out can be taken, held exclusively, or reserved for the other. Windows reports the last two as
//! WSAEACCES (10013), inside the Hyper-V/WinNAT excluded ranges that GitHub's runners carry, and it
//! hands out ephemeral ports in sequence, so draws from one allocator walk through such a range.

use std::io;
use std::net::SocketAddr;

use citadel_io::tokio::net::{TcpListener, UdpSocket};

/// How many ports a server draws, for a `:0` bind, looking for one free in both protocols.
const SERVER_PORT_DRAWS: usize = 8;

/// Whether a bind failed because of the port alone, so that another port cures it: held by
/// another socket (AddrInUse), or held exclusively or reserved for this protocol (PermissionDenied,
/// Windows' WSAEACCES).
pub(crate) fn twin_unavailable(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

/// The server's pair on `addr`. For an explicit port both binds take it or the caller sees why.
/// For `:0` the caller asked for any port, so a port the twin cannot take is given up and another
/// drawn, alternating which protocol's allocator draws: each allocator skips its own protocol's
/// reservations, so drawing from both means a range reserved for one cannot hold every draw.
pub(crate) fn draw_pair<T, U>(
    addr: SocketAddr,
    bind_tcp: impl Fn(SocketAddr) -> io::Result<(T, SocketAddr)>,
    bind_udp: impl Fn(SocketAddr) -> io::Result<(U, SocketAddr)>,
) -> io::Result<(T, U)> {
    let draws = if addr.port() == 0 {
        SERVER_PORT_DRAWS
    } else {
        1
    };
    let mut last = None;
    for draw in 0..draws {
        // Either bind of a draw can be refused for its port alone: on GitHub's Windows runners even
        // an any-port UDP bind was answered WSAEACCES (run 44824431193), so both count as a draw.
        let pair = if draw % 2 == 0 {
            bind_tcp(addr).and_then(|(tcp, at)| bind_udp(at).map(|(udp, _)| (tcp, udp)))
        } else {
            bind_udp(addr).and_then(|(udp, at)| bind_tcp(at).map(|(tcp, _)| (tcp, udp)))
        };
        match pair {
            Ok(pair) => return Ok(pair),
            Err(err) if twin_unavailable(&err) => {
                log::warn!(target: "citadel", "Draw {draw} for {addr}: the port is not free in both TCP and UDP ({err}); drawing another");
                last = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.expect("at least one draw"))
}

/// The client's QUIC socket: on its TCP signalling socket's address when UDP can take that port,
/// so one local address carries both (NAT and firewall state made for one serves the other); an
/// ephemeral port on the same IP otherwise. The shared port is a preference the QUIC connection
/// does not depend on.
pub(crate) fn beside_signalling<U>(
    signalling: SocketAddr,
    bind_udp: impl Fn(SocketAddr) -> io::Result<U>,
) -> io::Result<U> {
    match bind_udp(signalling) {
        Err(err) if twin_unavailable(&err) => {
            log::warn!(target: "citadel", "UDP cannot take {signalling} ({err}); QUIC uses an ephemeral port");
            bind_udp(SocketAddr::new(signalling.ip(), 0))
        }
        res => res,
    }
}

// The errno is kept (as `native_bind` keeps it): `twin_unavailable` reads its kind, and a caller
// reads the errno, which `to_string` reduced to English.
fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    citadel_wire::socket_helpers::get_udp_socket(addr)
        .map_err(|e| super::io_error_from_anyhow(e, io::ErrorKind::AddrNotAvailable))
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    citadel_wire::socket_helpers::get_tcp_listener(addr)
        .map_err(|e| super::io_error_from_anyhow(e, io::ErrorKind::AddrNotAvailable))
}

/// The server's TCP signalling listener and QUIC socket, on one address.
pub(crate) fn server_socket_pair(addr: SocketAddr) -> io::Result<(TcpListener, UdpSocket)> {
    draw_pair(
        addr,
        |at| {
            let tcp = bind_tcp(at)?;
            let bound = tcp.local_addr()?;
            Ok((tcp, bound))
        },
        |at| {
            let udp = bind_udp(at)?;
            let bound = udp.local_addr()?;
            Ok((udp, bound))
        },
    )
}

/// The client's QUIC socket, beside its TCP signalling socket when it can be.
pub(crate) fn client_quic_socket(signalling: SocketAddr) -> io::Result<UdpSocket> {
    beside_signalling(signalling, bind_udp)
}

#[cfg(test)]
#[path = "native_twin_ports_tests.rs"]
mod tests;
