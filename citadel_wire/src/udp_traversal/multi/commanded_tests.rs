//! The loser takes the socket the winner named, not any socket aimed at the winner's.
//!
//! The finished set below is the one two sessions on one host produce: each side binds two
//! sockets, every socket reaches every other, and the loser's two punchers each finish
//! against a different one of the winner's sockets.

use super::take;
use crate::udp_traversal::hole_punched_socket::{HolePunchedUdpSocket, TargettedSocketAddr};
use crate::udp_traversal::HolePunchID;
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use std::net::SocketAddr;

struct Winner {
    one: HolePunchID,
    two: HolePunchID,
    one_at: SocketAddr,
    two_at: SocketAddr,
}

fn winner() -> Winner {
    Winner {
        one: HolePunchID::new(),
        two: HolePunchID::new(),
        one_at: "127.0.0.1:41001".parse().unwrap(),
        two_at: "127.0.0.1:41002".parse().unwrap(),
    }
}

async fn finished(
    local_id: HolePunchID,
    remote: HolePunchID,
    at: SocketAddr,
) -> HolePunchedUdpSocket {
    HolePunchedUdpSocket {
        local_id,
        socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        addr: TargettedSocketAddr::new(at, at, remote),
    }
}

/// The defect: commanded `(a, winner.one)`, the loser held `a` aimed at `winner.two` and `b`
/// aimed at `winner.one`, and returned `b` -- the only one whose REMOTE matched. The winner,
/// committed to `a`, dialled a socket nobody listened on.
#[tokio::test]
async fn the_commanded_local_socket_is_taken_even_when_another_reached_the_winner() {
    let w = winner();
    let (a, b) = (HolePunchID::new(), HolePunchID::new());
    let mut set = vec![
        finished(a, w.two, w.two_at).await,
        finished(b, w.one, w.one_at).await,
    ];

    let socket = take(&mut set, a, w.one, None).expect("the commanded local socket finished");

    assert_eq!(
        socket.local_id, a,
        "the loser used a socket the winner did not name"
    );
    assert_eq!(
        socket.addr.unique_id, w.one,
        "the socket is not aimed at the winner's"
    );
    assert_eq!(socket.addr.send_address, w.one_at);
}

/// What the commanded socket saw the winner's socket at comes first: it is that socket's own
/// mapping, which another local socket's need not be.
#[tokio::test]
async fn the_commanded_sockets_own_observation_is_preferred() {
    let w = winner();
    let (a, b) = (HolePunchID::new(), HolePunchID::new());
    let seen: SocketAddr = "127.0.0.1:41999".parse().unwrap();
    let mut set = vec![
        finished(a, w.two, w.two_at).await,
        finished(b, w.one, w.one_at).await,
    ];

    let socket = take(
        &mut set,
        a,
        w.one,
        Some(TargettedSocketAddr::new(seen, seen, w.one)),
    )
    .expect("the commanded local socket finished");

    assert_eq!((socket.local_id, socket.addr.send_address), (a, seen));
}

#[tokio::test]
async fn an_exact_pair_is_taken_as_it_is() {
    let w = winner();
    let (a, b) = (HolePunchID::new(), HolePunchID::new());
    let mut set = vec![
        finished(b, w.one, w.one_at).await,
        finished(a, w.one, w.one_at).await,
    ];

    let socket = take(&mut set, a, w.one, None).expect("the exact pair finished");

    assert_eq!((socket.local_id, socket.addr.unique_id), (a, w.one));
    assert_eq!(set.len(), 1, "only the taken socket leaves the set");
}

/// A local socket that has not finished is answered by its own puncher (the kill command
/// names it), so nothing else may be substituted for it.
#[tokio::test]
async fn nothing_is_substituted_for_a_local_socket_that_has_not_finished() {
    let w = winner();
    let (a, b) = (HolePunchID::new(), HolePunchID::new());
    let mut set = vec![finished(b, w.one, w.one_at).await];

    assert!(take(&mut set, a, w.one, None).is_none());
    assert_eq!(
        set.len(),
        1,
        "a socket the command did not name was thrown away"
    );
}

/// Nor is a commanded socket aimed somewhere it has no address for.
#[tokio::test]
async fn a_commanded_socket_with_no_address_for_the_winner_stays() {
    let w = winner();
    let a = HolePunchID::new();
    let mut set = vec![finished(a, w.two, w.two_at).await];

    assert!(take(&mut set, a, w.one, None).is_none());
    assert_eq!(set.len(), 1);
}
