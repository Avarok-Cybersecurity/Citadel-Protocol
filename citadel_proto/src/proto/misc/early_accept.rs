//! A server accepts while it starts.
//!
//! A listener that is already bound queues connections in the kernel before the node starts
//! polling it. Tests and embedders pass such a listener in, and the address is known before the
//! node exists. Until the node polled it, a client's connect succeeded but its first packet never
//! came. So the server's own startup (loading the native root certificates, identifying its NAT)
//! counted against the client's transport deadline. On a loaded Mac the certificate load alone
//! took 8.8 s, and the client gave up at its 4 s `TCP_CONN_TIMEOUT` with "deadline has elapsed".
//!
//! [`accept_during`] polls the listener while the startup runs. Each connection gets its first
//! packet at once, and the connections wait for the node in [`EarlyAccepted`], in order.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use citadel_io::tokio_stream::Stream;

/// A listener, and the connections it accepted before the node took it over.
pub struct EarlyAccepted<L: Stream> {
    early: VecDeque<L::Item>,
    listener: L,
    ended: bool,
}

/// Runs `startup` while accepting from `listener`, and returns the startup's output and the
/// listener, carrying what it accepted meanwhile.
pub(crate) async fn accept_during<L: Stream + Unpin, F: Future>(
    listener: L,
    startup: F,
) -> (F::Output, EarlyAccepted<L>) {
    let mut accepted = EarlyAccepted {
        early: VecDeque::new(),
        listener,
        ended: false,
    };
    let mut startup = std::pin::pin!(startup);
    let out = std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = startup.as_mut().poll(cx) {
            return Poll::Ready(out);
        }
        while !accepted.ended {
            match Pin::new(&mut accepted.listener).poll_next(cx) {
                Poll::Ready(Some(item)) => accepted.early.push_back(item),
                Poll::Ready(None) => accepted.ended = true,
                Poll::Pending => break,
            }
        }
        Poll::Pending
    })
    .await;
    (out, accepted)
}

// The queued connections are moved, never pinned, so only the listener decides.
impl<L: Stream + Unpin> Unpin for EarlyAccepted<L> {}

impl<L: Stream + Unpin> Stream for EarlyAccepted<L> {
    type Item = L::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(item) = this.early.pop_front() {
            return Poll::Ready(Some(item));
        }
        if this.ended {
            return Poll::Ready(None);
        }
        Pin::new(&mut this.listener).poll_next(cx)
    }
}

#[cfg(test)]
#[path = "early_accept_tests.rs"]
mod tests;
