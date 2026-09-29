//! Orderings of the winner/loser handshake that used to fail one side while
//! both sides held a working socket. Each test drives two real `Coordination`s
//! over an in-process `NetworkEndpoint` pair and forces one ordering.

use super::{receive, Coordination, DualStackCandidateSignal};
use crate::udp_traversal::HolePunchID;
use citadel_io::tokio;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

/// Generous for a loopback round trip; only ever reached by a failing run.
const DEADLINE: Duration = Duration::from_secs(5);
/// How long a winner is given to (wrongly) finish on a signal that is not
/// `WinnerCanEnd`. A loopback message arrives in well under this.
const WRONG_EXIT_WINDOW: Duration = Duration::from_millis(300);

struct Pair {
    winner: Coordination,
    loser: Coordination,
    // Held so the multiplexed connection outlives the channels.
    _endpoints: (NetworkEndpoint, NetworkEndpoint),
}

async fn pair() -> Pair {
    let (a, b) = create_streams_with_addrs().await;
    let (winner, loser) = tokio::join!(Coordination::open(&a), Coordination::open(&b));
    Pair {
        winner: winner.unwrap(),
        loser: loser.unwrap(),
        _endpoints: (a, b),
    }
}

/// Race 3: `WinnerCanEnd` arrives while the winner's reader is still running,
/// i.e. before the winner's `select!` has observed its own `done`. The reader
/// consumes it, the loser finishes and hangs up, and the winner's later wait
/// used to see only the hang-up and fail.
#[tokio::test]
async fn a_release_consumed_by_the_reader_still_releases_the_winner() {
    let Pair { winner, loser, .. } = pair().await;

    loser.release_winner().await.unwrap();
    tokio::time::timeout(DEADLINE, winner.read_signals())
        .await
        .expect("the reader never received the release")
        .unwrap();
    drop(loser);

    let res = tokio::time::timeout(DEADLINE, winner.await_winner_can_end())
        .await
        .expect("the winner hung after being released");
    assert!(
        res.is_ok(),
        "the winner failed although the loser had released it: {res:?}"
    );
}

/// Race 2, loser side: once commanded, the loser's rebuilder owns the outcome,
/// so its punchers all failing locally must not put `AllFailed` on the wire.
#[tokio::test]
async fn a_commanded_loser_does_not_report_all_failed() {
    let Pair { winner, loser, .. } = pair().await;
    *loser.commanded_winner.lock().await = Some((HolePunchID::new(), HolePunchID::new()));

    loser.on_local_all_failed().await.unwrap();
    loser.release_winner().await.unwrap();

    let first = tokio::time::timeout(DEADLINE, receive(&mut *winner.conn_rx.lock().await))
        .await
        .expect("nothing reached the winner")
        .unwrap();
    assert!(
        matches!(first, DualStackCandidateSignal::WinnerCanEnd),
        "a commanded loser told the winner {first:?}"
    );
}

/// Race 2, winner side: `AllFailed` can still cross a `Winner` in flight. The
/// winner has committed its socket, and the loser may yet rebuild the commanded
/// one, so only `WinnerCanEnd` (or the loser hanging up) may end the wait.
#[tokio::test]
async fn a_winner_waits_past_a_crossing_all_failed() {
    let Pair { winner, loser, .. } = pair().await;

    loser.on_local_all_failed().await.unwrap();

    let wait = winner.await_winner_can_end();
    tokio::pin!(wait);
    assert!(
        tokio::time::timeout(WRONG_EXIT_WINDOW, &mut wait)
            .await
            .is_err(),
        "the winner finished on AllFailed, before the loser released it"
    );

    loser.release_winner().await.unwrap();
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the winner hung after being released")
        .unwrap();
}

/// Race 2, loser side: the loser already holds the commanded socket, so a
/// winner that has hung up cannot make the loser fail.
#[tokio::test]
async fn a_loser_holding_its_socket_is_not_failed_by_a_departed_winner() {
    let Pair { winner, loser, .. } = pair().await;

    drop(winner);
    // As in `drive`: the loser's reader is still running while its rebuilder
    // works, and it is the one that sees the hang-up.
    let read = tokio::time::timeout(DEADLINE, loser.read_signals())
        .await
        .expect("the loser never saw the winner hang up");
    assert!(read.is_err());

    let res = loser.release_winner().await;
    assert!(
        res.is_ok(),
        "the loser failed while holding its socket: {res:?}"
    );
}

/// The failure path stays a failure: a loser that hangs up without releasing
/// the winner fails the winner too, so both sides retry together.
#[tokio::test]
async fn a_winner_fails_when_the_loser_hangs_up_unreleased() {
    let Pair { winner, loser, .. } = pair().await;

    loser.on_local_all_failed().await.unwrap();
    drop(loser);

    let res = tokio::time::timeout(DEADLINE, winner.await_winner_can_end())
        .await
        .expect("the winner hung after the loser left");
    assert!(res.is_err());
}
