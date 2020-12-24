use std::sync::Arc;
use std::pin::Pin;
use parking_lot::Mutex;
use futures::Future;
use futures::task::{Context, Poll};

pub mod clean_shutdown;
pub mod net;

/// For denoting to the compiler that running the future is thread-safe
pub struct ThreadSafeFuture<'a, Out: 'a>(Arc<Mutex<Pin<Box<dyn Future<Output=Out> + 'a>>>>);

impl<'a, Out: 'a> ThreadSafeFuture<'a, Out> {
    /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
    pub fn new(fx: impl Future<Output=Out> + 'a) -> Self {
        Self(Arc::new(Mutex::new(Box::pin(fx))))
    }
}

unsafe impl<'a, Out: 'a> Send for ThreadSafeFuture<'a, Out> {}
unsafe impl<'a, Out: 'a> Sync for ThreadSafeFuture<'a, Out> {}

impl<'a, Out: 'a> Future for ThreadSafeFuture<'a, Out> {
    type Output = Out;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut lock = self.0.lock();
        lock.as_mut().poll(cx)
    }
}