//! Panic-Safe Future Implementation
//!
//! This module provides a future wrapper that safely handles panics in async code.
//! It ensures that panics are caught and converted into proper error results
//! rather than propagating and potentially crashing the entire process.
//!
//! # Features
//!
//! - Panic catching
//! - Error conversion
//! - Future wrapping
//! - Safe unwinding
//!
//! # Important Notes
//!
//! - Converts panics to errors
//! - Thread-safe operation
//! - Zero overhead when no panic
//! - Preserves error types
//!
//! # Related Components
//!
//! - `kernel_executor.rs`: Task execution
//! - `clean_shutdown.rs`: Resource cleanup
//! - `error.rs`: Error handling
//! - `ordered_channel.rs`: Message handling

use citadel_io::tokio::macros::support::{Pin, Poll};
use citadel_io::tokio::task::{JoinError, JoinHandle};
use futures::task::Context;
use std::future::Future;

/// Ensures that if a panic occurs in a task, the panic backtrace prints and halts the program
pub struct ExplicitPanicFuture<F> {
    future: JoinHandle<F>,
}

impl<F> ExplicitPanicFuture<F> {
    pub fn new(future: JoinHandle<F>) -> Self {
        Self { future }
    }
}

impl<F> Future for ExplicitPanicFuture<F> {
    type Output = Result<F, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(Pin::new(&mut self.future).poll(cx)) {
            Err(err) => {
                if err.is_panic() {
                    std::panic::panic_any(err.into_panic())
                } else {
                    Poll::Ready(Err(err))
                }
            }

            res => Poll::Ready(res),
        }
    }
}

/// A spawned task owned by the code that spawned it: dropping this handle aborts the task, so a
/// task never outlives the scope that awaits it. A panic inside the task is re-raised on await,
/// as with [`ExplicitPanicFuture`].
pub struct OwnedTask<F>(ExplicitPanicFuture<F>);

impl<F> OwnedTask<F> {
    pub fn new(future: JoinHandle<F>) -> Self {
        Self(ExplicitPanicFuture::new(future))
    }
}

impl<F> Future for OwnedTask<F> {
    type Output = Result<F, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<F> Drop for OwnedTask<F> {
    fn drop(&mut self) {
        self.0.future.abort();
    }
}

/// Runs `future`, turning a panic inside it into `Err` with the panic's message, so the code after
/// it still runs. A session's teardown must run even when one of its packet handlers panicked:
/// skipped, the session stays registered and its CID reads as connected until a restart.
pub fn catch_panic<F: Future>(future: F) -> CatchPanic<F> {
    CatchPanic(Box::pin(future))
}

/// See [`catch_panic`].
pub struct CatchPanic<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchPanic<F> {
    type Output = Result<F::Output, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let future = self.0.as_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(panic) => Poll::Ready(Err(panic_message(panic.as_ref()))),
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    // `ExplicitPanicFuture` re-raises a task's panic with the task's payload boxed once more.
    if let Some(inner) = panic.downcast_ref::<Box<dyn std::any::Any + Send>>() {
        return panic_message(inner.as_ref());
    }
    panic
        .downcast_ref::<&str>()
        .map(|message| message.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a non-string payload".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;

    #[tokio::test]
    async fn a_panic_inside_the_future_is_returned_as_an_error() {
        let outcome = catch_panic(async {
            tokio::task::yield_now().await;
            panic!("handler failed");
        })
        .await;
        assert_eq!(outcome, Err::<(), _>("handler failed".to_string()));
    }

    #[tokio::test]
    async fn a_panic_in_a_spawned_task_reraised_by_explicit_panic_future_is_returned() {
        let task = tokio::task::spawn(async { panic!("{}", "in the task") });
        let outcome = catch_panic(ExplicitPanicFuture::new(task)).await;
        assert_eq!(outcome.map(|_| ()), Err("in the task".to_string()));
    }

    #[tokio::test]
    async fn dropping_an_owned_task_ends_it_and_releases_what_it_held() {
        let held = std::sync::Arc::new(());
        let probe = std::sync::Arc::downgrade(&held);
        let task = OwnedTask::new(tokio::task::spawn(async move {
            let _held = held;
            std::future::pending::<()>().await
        }));
        tokio::task::yield_now().await;
        assert!(probe.upgrade().is_some());
        drop(task);
        // Aborting is asynchronous: the runtime drops the task's future on its next turn. The
        // deadline only bounds that turn.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while probe.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the task outlived its dropped handle");
    }

    #[tokio::test]
    async fn an_owned_task_returns_its_output() {
        assert_eq!(
            OwnedTask::new(tokio::task::spawn(async { 7 }))
                .await
                .unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn an_output_passes_through() {
        assert_eq!(catch_panic(async { 7 }).await, Ok(7));
    }
}
