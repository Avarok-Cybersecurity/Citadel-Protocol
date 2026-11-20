use super::runnable_window;
use citadel_io::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_millis(500);

/// A stall longer than the window leaves the window open: the stall happened while the caller
/// could not run, so it does not count.
#[citadel_io::tokio::test(flavor = "current_thread")]
async fn a_stall_longer_than_the_window_does_not_spend_it() {
    let window = runnable_window(WINDOW);
    citadel_io::tokio::pin!(window);
    assert!(
        citadel_io::tokio::time::timeout(Duration::from_millis(100), &mut window)
            .await
            .is_err()
    );
    std::thread::sleep(WINDOW * 3);
    let resumed = Instant::now();
    assert!(
        citadel_io::tokio::time::timeout(Duration::from_millis(100), &mut window)
            .await
            .is_err(),
        "the stall spent the window"
    );
    window.await;
    assert!(resumed.elapsed() >= WINDOW / 2, "{:?}", resumed.elapsed());
}

/// Without a stall, the window is its length.
#[citadel_io::tokio::test(flavor = "current_thread")]
async fn without_a_stall_the_window_is_its_length() {
    let started = Instant::now();
    runnable_window(WINDOW).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= WINDOW, "{elapsed:?}");
    assert!(elapsed < WINDOW * 2, "{elapsed:?}");
}
