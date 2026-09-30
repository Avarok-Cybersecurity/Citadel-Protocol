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

    loser.release_winner().await;
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
    loser.release_winner().await;

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

    loser.release_winner().await;
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

    // Returns `()`: there is no longer a way for it to fail the loser. What it
    // must still do is return, rather than wait on a winner that is gone.
    tokio::time::timeout(DEADLINE, loser.release_winner())
        .await
        .expect("the loser hung on a departed winner");
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

/// Found by the stall loop: receiving `AllFailed` used to echo `AllFailed`
/// back from a side that had not failed. The failed side read the echo as
/// "both failed" and ended its reader, so the `Winner` the other side sent once
/// one of its punchers succeeded was never taken, and both sat until timeout.
#[tokio::test]
async fn a_remote_failure_is_not_echoed_so_the_failed_side_can_still_be_commanded() {
    let Pair {
        winner: eventual_winner,
        loser: failed_side,
        ..
    } = pair().await;

    failed_side.on_local_all_failed().await.unwrap();
    assert!(
        tokio::time::timeout(WRONG_EXIT_WINDOW, eventual_winner.read_signals())
            .await
            .is_err(),
        "a side that has not failed stopped reading on the remote's AllFailed"
    );

    let command = (HolePunchID::new(), HolePunchID::new());
    eventual_winner
        .announce_winner(command.0, command.1)
        .await
        .unwrap();
    let read = tokio::time::timeout(WRONG_EXIT_WINDOW, failed_side.read_signals()).await;
    assert!(
        read.is_err(),
        "the failed side stopped reading before the Winner: {read:?}"
    );
    assert_eq!(
        *failed_side.commanded_winner.lock().await,
        Some(command),
        "the failed side never took the Winner"
    );
}

/// Stall sensitivity of the positive assertion in
/// `a_remote_failure_is_not_echoed_so_the_failed_side_can_still_be_commanded`:
/// it requires the Winner to be TAKEN inside `WRONG_EXIT_WINDOW`, a wall-clock
/// window. Freeze the current_thread runtime for longer than that window just
/// after the window is armed and before the announcer's writer has run, as a
/// symbolizing backtrace or a laptop pause does. The product loses nothing: the
/// Winner is on the wire and the reader takes it as soon as it runs again. The
/// window's timer and the reader wake on the same tick, the timer is checked
/// first, and the test fails although the ordering it means still held.
#[tokio::test]
async fn a_winner_announced_before_a_runtime_stall_is_still_taken() {
    let Pair {
        winner: eventual_winner,
        loser: failed_side,
        ..
    } = pair().await;

    failed_side.on_local_all_failed().await.unwrap();
    let command = (HolePunchID::new(), HolePunchID::new());
    eventual_winner
        .announce_winner(command.0, command.1)
        .await
        .unwrap();

    let stall = async {
        std::thread::sleep(WRONG_EXIT_WINDOW + Duration::from_millis(200));
    };
    let (read, ()) = tokio::join!(
        tokio::time::timeout(WRONG_EXIT_WINDOW, failed_side.read_signals()),
        stall
    );
    assert!(
        read.is_err(),
        "the failed side stopped reading before the Winner: {read:?}"
    );
    let taken_in_window = *failed_side.commanded_winner.lock().await;

    // The Winner was never lost: the next signal on the wire is it.
    let late = tokio::time::timeout(DEADLINE, async {
        loop {
            match receive(&mut *failed_side.conn_rx.lock().await).await {
                Ok(DualStackCandidateSignal::Winner(local, peer)) => return Some((local, peer)),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();

    assert_eq!(
        taken_in_window,
        Some(command),
        "the Winner was taken only after the wall-clock window (late read: {late:?}), \
         so the assertion measured the stall, not the protocol"
    );
}
