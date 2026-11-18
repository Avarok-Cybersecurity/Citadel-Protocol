//! The loser's half of a winner's command: which of its finished sockets it must use.
//!
//! The winner names a PAIR, `(loser's socket, winner's socket)`, and commits its own half at
//! once: as the QUIC client it dials the named loser socket's address, and as the server it
//! listens on its own socket. The loser must therefore come back with the named LOCAL socket,
//! aimed at the named REMOTE socket. Matching on the remote alone is not enough, because one
//! remote socket can be reached from several local ones -- on one host every socket reaches
//! every other, which is the topology of two sessions in one agent. A loser that returned a
//! different local socket aimed at the right remote left the winner dialling a socket nobody
//! listened on: the client side failed its handshake in seconds, the server side waited out
//! the whole attempt, and the connection stayed relayed with no UDP channel.

use crate::udp_traversal::hole_punched_socket::{HolePunchedUdpSocket, TargettedSocketAddr};
use crate::udp_traversal::HolePunchID;
use std::net::SocketAddr;

/// Takes the socket for the commanded pair out of `finished`, or `None` if this side holds no
/// finished socket for `local` (a puncher still running answers the command itself).
///
/// The commanded local socket finished against a different remote socket when this side's
/// puncher completed with the winner's other socket first. It is then aimed at `remote`:
/// at `observed`, the address that socket itself saw `remote` at, when it saw one; otherwise
/// at the address another finished socket reached `remote` at, if that one shares its
/// address family. A local socket with no address for `remote` stays where it is.
pub(super) fn take(
    finished: &mut Vec<HolePunchedUdpSocket>,
    local: HolePunchID,
    remote: HolePunchID,
    observed: Option<TargettedSocketAddr>,
) -> Option<HolePunchedUdpSocket> {
    let position = finished.iter().position(|s| s.local_id == local)?;
    if finished[position].addr.unique_id == remote {
        return Some(finished.swap_remove(position));
    }
    let family = finished[position].local_addr().ok().map(|a| a.is_ipv4());
    let addr = observed.or_else(|| {
        finished
            .iter()
            .map(|s| s.addr)
            .find(|a| a.unique_id == remote && family == Some(reachable_family(a.send_address)))
    })?;
    let mut socket = finished.swap_remove(position);
    socket.addr = addr;
    Some(socket)
}

/// The family a socket must be bound in to send to `addr`.
fn reachable_family(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
    }
}

#[cfg(test)]
#[path = "commanded_tests.rs"]
mod tests;
