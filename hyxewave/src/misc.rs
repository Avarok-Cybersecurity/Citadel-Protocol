use std::pin::Pin;
use std::future::Future;
use std::task::{Context, Poll};

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