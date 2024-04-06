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
