//! A spawned task that stops when you stop waiting for it.
//!
//! Dropping a tokio `JoinHandle` **detaches** the task; it does not abort it.
//! That is the right default for fire-and-forget work and the wrong one for
//! everything in the hole-punch driver, which is wrapped in a timeout and
//! retried:
//!
//! ```text
//! driver()                       // up to MAX_RETRIES attempts
//!   timeout(driver_inner(..))    // on timeout the inner future is DROPPED
//!     DualStackUdpHolePuncher    // dropped
//!       JoinHandle<drive(..)>    // dropped -> DETACHED, still running
//!         N x JoinHandle<..>     // also dropped, also still running
//! ```
//!
//! `drive` has no exit path on failure — it ends by waiting on a `done` signal
//! or a rebuilder, neither of which arrives once nobody is listening — so each
//! timed-out attempt left a task looping forever, holding its bound UDP sockets
//! and a 100ms retransmit timer. The retry loop then bound a fresh set and did
//! it again. Nothing errored, and the sockets were never released for the
//! lifetime of the process.
//!
//! Wrapping the handle makes the intent explicit and non-optional: as long as
//! somebody awaits the task it runs; the moment the awaiting future is dropped,
//! so is the task.

use futures::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A `JoinHandle` that aborts its task on drop, and forwards `poll` otherwise.
///
/// `T` is the task's output. Polling yields `Err` if the task panicked or was
/// aborted, exactly as awaiting a `JoinHandle` does.
pub struct AbortOnDrop<T> {
    handle: citadel_io::tokio::task::JoinHandle<T>,
}

impl<T> AbortOnDrop<T> {
    /// Spawn `future` such that dropping the returned handle aborts it.
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        Self {
            handle: citadel_io::tokio::task::spawn(future),
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        // Idempotent, and a no-op once the task has finished.
        self.handle.abort();
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, citadel_io::tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A task that never returns, so only cancellation can stop it — the shape
    /// of `drive` once its peer has stopped listening.
    async fn forever(ticks: Arc<AtomicUsize>) {
        loop {
            ticks.fetch_add(1, Ordering::SeqCst);
            citadel_io::tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn settle() {
        citadel_io::tokio::time::sleep(Duration::from_millis(60)).await;
    }

    #[tokio::test]
    async fn dropping_the_handle_stops_the_task() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let handle = AbortOnDrop::spawn(forever(ticks.clone()));

        settle().await;
        let while_held = ticks.load(Ordering::SeqCst);
        assert!(while_held > 0, "the task never ran at all");

        drop(handle);
        settle().await;
        let after_drop = ticks.load(Ordering::SeqCst);

        settle().await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after_drop,
            "the task kept running after its handle was dropped"
        );
    }

    /// The control for the test above, kept as a test rather than run once by
    /// hand: it pins that a bare `spawn` really does detach, so
    /// `dropping_the_handle_stops_the_task` is measuring the wrapper and not
    /// something the runtime would have done anyway.
    #[tokio::test]
    async fn a_bare_join_handle_detaches_instead() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let handle = citadel_io::tokio::task::spawn(forever(ticks.clone()));

        settle().await;
        drop(handle);
        settle().await;
        let after_drop = ticks.load(Ordering::SeqCst);

        settle().await;
        assert!(
            ticks.load(Ordering::SeqCst) > after_drop,
            "a bare JoinHandle stopped its task on drop; the wrapper under test \
             would then be measuring nothing"
        );
    }

    #[tokio::test]
    async fn a_completed_task_still_yields_its_value() {
        let handle = AbortOnDrop::spawn(async { 7u8 });
        assert_eq!(handle.await.unwrap(), 7);
    }

    /// Aborting an already-finished task must not turn its success into an
    /// error, or every successful traversal would report a JoinError on the way
    /// out.
    #[tokio::test]
    async fn finishing_before_the_drop_is_not_an_abort() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = ticks.clone();
        let handle = AbortOnDrop::spawn(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        settle().await;
        assert!(handle.await.is_ok(), "a finished task reported an error");
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }
}
