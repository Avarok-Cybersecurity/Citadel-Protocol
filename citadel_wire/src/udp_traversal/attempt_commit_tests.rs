//! The orderings around an attempt's timer, forced on paused time.

use super::{until_committed, AttemptCommit};
use citadel_io::tokio;
use std::time::Duration;

const TIMER: Duration = Duration::from_secs(20);

/// The CI failure, as one side saw it: the winner sent `Winner` (committed)
/// late in its attempt, the loser took the pair and returned, and the
/// winner's `WinnerCanEnd` arrived after its 20 s timer. The timer used to
/// abandon the attempt there, so the winner retried against a peer that had
/// already returned, until the whole punch budget ran out.
#[tokio::test(start_paused = true)]
async fn an_attempt_committed_before_its_timer_runs_to_its_end() {
    let commit = AttemptCommit::new();
    let task = {
        let commit = commit.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(19)).await;
            assert!(commit.commit(), "an open attempt refused to commit");
            tokio::time::sleep(Duration::from_secs(2)).await;
            "punched"
        }
    };

    let output = until_committed(TIMER, &commit, task).await;

    assert_eq!(
        output,
        Some("punched"),
        "a committed attempt was abandoned on its timer"
    );
}

/// The timer still bounds an attempt nobody committed to.
#[tokio::test(start_paused = true)]
async fn an_uncommitted_attempt_ends_at_its_timer() {
    let commit = AttemptCommit::new();
    let started = tokio::time::Instant::now();

    let output = until_committed(TIMER, &commit, std::future::pending::<()>()).await;

    assert_eq!(output, None);
    assert_eq!(started.elapsed(), TIMER);
}

/// The race the two tasks can run: once the timer has expired the attempt, the
/// punch must not tell the peer anything.
#[tokio::test(start_paused = true)]
async fn an_expired_attempt_cannot_commit() {
    let commit = AttemptCommit::new();
    let _ = until_committed(TIMER, &commit, std::future::pending::<()>()).await;

    assert!(!commit.commit(), "an expired attempt still committed");
}

/// A side commits once whichever role it has; committing again is not a race lost.
#[test]
fn committing_twice_still_commits() {
    let commit = AttemptCommit::new();
    assert!(commit.commit());
    assert!(commit.commit());
}
