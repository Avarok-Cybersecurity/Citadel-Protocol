use super::{runnable_timeout, runnable_window, RunnableElapsed};
use crate::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_millis(500);

/// A stall longer than the window leaves the window open: the stall happened while the caller
/// could not run, so it does not count.
#[crate::tokio::test(flavor = "current_thread")]
async fn a_stall_longer_than_the_window_does_not_spend_it() {
    let window = runnable_window(WINDOW);
    crate::tokio::pin!(window);
    assert!(
        crate::tokio::time::timeout(Duration::from_millis(100), &mut window)
            .await
            .is_err()
    );
    std::thread::sleep(WINDOW * 3);
    let resumed = Instant::now();
    assert!(
        crate::tokio::time::timeout(Duration::from_millis(100), &mut window)
            .await
            .is_err(),
        "the stall spent the window"
    );
    window.await;
    assert!(resumed.elapsed() >= WINDOW / 2, "{:?}", resumed.elapsed());
}

/// Without a stall, the window is its length.
#[crate::tokio::test(flavor = "current_thread")]
async fn without_a_stall_the_window_is_its_length() {
    let started = Instant::now();
    runnable_window(WINDOW).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= WINDOW, "{elapsed:?}");
    assert!(elapsed < WINDOW * 2, "{elapsed:?}");
}

/// A real hang: work that never finishes, on a caller that runs freely, spends the budget at its
/// nominal length and is reported.
#[crate::tokio::test(flavor = "current_thread")]
async fn a_hang_is_caught_at_the_budget() {
    let started = Instant::now();
    let outcome = runnable_timeout(WINDOW, std::future::pending::<()>()).await;
    let elapsed = started.elapsed();
    assert_eq!(outcome, Err(RunnableElapsed(WINDOW)));
    assert!(elapsed >= WINDOW, "{elapsed:?}");
    assert!(elapsed < WINDOW * 2, "{elapsed:?}");
}

/// Work that finishes inside the budget returns its output.
#[crate::tokio::test(flavor = "current_thread")]
async fn work_within_the_budget_returns_its_output() {
    let outcome = runnable_timeout(WINDOW, async {
        crate::time::sleep(WINDOW / 5).await;
        7
    })
    .await;
    assert_eq!(outcome, Ok(7));
}

/// A stall longer than the budget does not spend it: the work finishes after the stall and its
/// output is returned, where a wall-clock timeout would have reported a hang.
#[crate::tokio::test(flavor = "current_thread")]
async fn a_stall_does_not_spend_a_budget() {
    let outcome = runnable_timeout(WINDOW, async {
        crate::time::sleep(Duration::from_millis(50)).await;
        std::thread::sleep(WINDOW * 3);
        crate::time::sleep(WINDOW / 5).await;
        7
    })
    .await;
    assert_eq!(outcome, Ok(7));
}
