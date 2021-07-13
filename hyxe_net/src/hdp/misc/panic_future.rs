use std::future::Future;
use tokio::task::{JoinHandle, JoinError};
use futures::task::Context;
use tokio::macros::support::{Pin, Poll};
use crate::macros::LocalContextRequirements;

/// Ensures that if a panic occurs in a task, the panic backtrace prints and halts the program
pub struct ExplicitPanicFuture<F> {
    future: JoinHandle<F>
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

            res => Poll::Ready(res)
        }
    }
}

/// For denoting to the compiler that running the future is thread-safe
/// It is up to the caller to ensure the supplied future is not going to be called
/// from multiple threads concurrently. IF there is a single instance of the task, then
/// use this. If there will be multiple, use the safer version in misc::

pub struct AssertSendSafeFuture<'a, Out: 'a>(Pin<Box<dyn Future<Output=Out> + 'a>>);

unsafe impl<'a, Out: 'a> Send for AssertSendSafeFuture<'a, Out> {}

impl<'a, Out: 'a> AssertSendSafeFuture<'a, Out> {
    /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
    pub fn new(fx: impl Future<Output=Out> + 'a) -> Self {
        Self(Box::pin(fx))
    }
}

impl<'a, Out: 'a> Future for AssertSendSafeFuture<'a, Out> {
    type Output = Out;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

pub struct LiteFuture<'a, Out: 'a>(Pin<Box<dyn LiteFutureImpl<'a, Out>>>);
pub trait LiteFutureImpl<'a, Out: 'a>: Future<Output=Out> + LocalContextRequirements<'a> {}
impl<'a, Out: 'a, F: Future<Output=Out> + LocalContextRequirements<'a>> LiteFutureImpl<'a, Out> for F {}

impl<'a, Out> LiteFuture<'a, Out> {
    pub fn new<F: LiteFutureImpl<'a, Out>>(future: F) -> Self {
        Self(Box::pin(future))
    }
}

impl<'a, Out: 'a> Future for LiteFuture<'a, Out> {
    type Output = Out;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}