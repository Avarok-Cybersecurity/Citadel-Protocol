//! Race 1: the loser's poller re-sends the kill command every 100 ms on a
//! channel that holds one message per puncher. A puncher task that is not
//! polled between two sends sees `Lagged`, and that used to be read as "the
//! command names another puncher": it ended with `FirewallSkip` and its socket
//! was dropped, although the command named it.

use super::SingleUDPHolePuncher;
use crate::socket_helpers::get_udp_socket;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use crate::udp_traversal::{HolePunchID, NatTraversalMethod};
use citadel_io::tokio;
use citadel_io::ErrorCode;
use netbeam::sync::RelativeNodeType;

/// A puncher aimed at a socket that never answers, so method3 cannot finish
/// before the kill command is read.
fn puncher_aimed_at_silence() -> (SingleUDPHolePuncher, std::net::UdpSocket) {
    let silent_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let puncher = SingleUDPHolePuncher::new(
        RelativeNodeType::Initiator,
        HolePunchConfigContainer::default(),
        get_udp_socket("127.0.0.1:0").unwrap(),
        vec![silent_peer.local_addr().unwrap()],
    )
    .unwrap();
    (puncher, silent_peer)
}

async fn obey(
    puncher: &mut SingleUDPHolePuncher,
    sends_before_first_poll: usize,
    command: (HolePunchID, HolePunchID),
) -> (ErrorCode, Option<Option<()>>) {
    // Capacity 1: one puncher, as `drive` sizes it.
    let (kill_tx, kill_rx) = tokio::sync::broadcast::channel(1);
    let (rebuild_tx, mut rebuild_rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..sends_before_first_poll {
        kill_tx.send(command).unwrap();
    }

    let err = puncher
        .try_method(NatTraversalMethod::Method3, kill_rx, rebuild_tx)
        .await
        .expect_err("method3 cannot succeed against a silent peer");
    let reported = rebuild_rx.try_recv().ok().map(|s| s.map(|_| ()));
    (err.code, reported)
}

#[tokio::test]
async fn a_command_that_lagged_is_still_obeyed() {
    let (mut puncher, _silent) = puncher_aimed_at_silence();
    let command = (puncher.get_unique_id(), HolePunchID::new());

    let (code, reported) = obey(&mut puncher, 3, command).await;

    assert_ne!(
        code,
        ErrorCode::FirewallSkip,
        "a command naming this puncher was read as naming another"
    );
    assert_ne!(
        reported,
        Some(None),
        "the puncher reported it was not the one commanded"
    );
    // The command named it, but method3 never saw the peer's id, so there is
    // no socket to rebuild; the puncher is left for the rebuilder, socket intact.
    assert_eq!(code, ErrorCode::FirewallKillSwitchNoMatch);
    assert!(puncher.take_socket().is_some());
}

/// The control: a command naming another puncher still ends this one.
#[tokio::test]
async fn a_command_for_another_puncher_still_ends_this_one() {
    let (mut puncher, _silent) = puncher_aimed_at_silence();
    let command = (HolePunchID::new(), HolePunchID::new());

    let (code, reported) = obey(&mut puncher, 3, command).await;

    assert_eq!(code, ErrorCode::FirewallSkip);
    assert_eq!(reported, Some(None));
}
