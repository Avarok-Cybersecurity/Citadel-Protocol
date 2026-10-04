//! WebSocket-level ping/pong for a C2S link carried by a WebSocket.
//!
//! A liveness probe (`proto::server_probe`) also asks the WebSocket under it to send a ping, so
//! the path is exercised at the transport too: an HTTP edge in between sees traffic, and a dead
//! TCP connection fails its next write rather than waiting for the keep-alive. Pongs to the
//! other side's pings are answered by tungstenite on the next read or write.
//!
//! [`WsPinger`] is shared between the session (which asks for pings) and the byte stream (which
//! writes them before its next frame and reads the pongs). On wasm the type is only named: a
//! browser WebSocket cannot send pings, so `PlatformOps::ws_pinger` is `None` there.
#![cfg_attr(target_family = "wasm", allow(dead_code))]

use citadel_io::tokio::sync::watch;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A ping's payload: its sequence number, big-endian.
pub(crate) const PING_PAYLOAD_LEN: usize = 8;

#[derive(Clone)]
pub struct WsPinger(Arc<Shared>);

struct Shared {
    next: AtomicU64,
    queued: citadel_io::Mutex<VecDeque<u64>>,
    /// The highest ping sequence the other side has answered; 0 before any.
    answered: watch::Sender<u64>,
}

impl WsPinger {
    pub(crate) fn new() -> Self {
        let (answered, _) = watch::channel(0);
        Self(Arc::new(Shared {
            next: AtomicU64::new(1),
            queued: citadel_io::Mutex::new(VecDeque::new()),
            answered,
        }))
    }

    /// Queues a ping; it is written before the stream's next frame. Returns its sequence number.
    pub fn ping(&self) -> u64 {
        let seq = self.0.next.fetch_add(1, Ordering::Relaxed);
        self.0.queued.lock().push_back(seq);
        seq
    }

    /// Wakes whenever the other side answers a ping, with the highest sequence answered.
    pub fn answered(&self) -> watch::Receiver<u64> {
        self.0.answered.subscribe()
    }

    /// The next ping to write, if any, as its payload.
    pub(crate) fn next_queued(&self) -> Option<[u8; PING_PAYLOAD_LEN]> {
        self.0.queued.lock().pop_front().map(u64::to_be_bytes)
    }

    /// A ping that could not be written goes back to the front of the queue.
    pub(crate) fn requeue(&self, payload: [u8; PING_PAYLOAD_LEN]) {
        self.0.queued.lock().push_front(u64::from_be_bytes(payload));
    }

    /// A pong arrived. One whose payload is not a ping of ours is ignored.
    pub(crate) fn on_pong(&self, payload: &[u8]) {
        let Ok(bytes) = <[u8; PING_PAYLOAD_LEN]>::try_from(payload) else {
            return;
        };
        let seq = u64::from_be_bytes(bytes);
        if seq == 0 || seq >= self.0.next.load(Ordering::Relaxed) {
            return;
        }
        self.0.answered.send_if_modified(|answered| {
            let newer = seq > *answered;
            if newer {
                *answered = seq;
            }
            newer
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pong_to_a_sent_ping_counts() {
        let pinger = WsPinger::new();
        let answered = pinger.answered();
        pinger.on_pong(&1u64.to_be_bytes());
        assert_eq!(*answered.borrow(), 0, "no ping 1 was sent yet");
        let seq = pinger.ping();
        assert_eq!(pinger.next_queued(), Some(seq.to_be_bytes()));
        assert_eq!(pinger.next_queued(), None);
        pinger.on_pong(b"not eight");
        assert_eq!(*answered.borrow(), 0);
        pinger.on_pong(&seq.to_be_bytes());
        assert_eq!(*answered.borrow(), seq);
    }

    #[test]
    fn a_requeued_ping_is_written_first() {
        let pinger = WsPinger::new();
        let first = pinger.ping();
        let second = pinger.ping();
        let payload = pinger.next_queued().unwrap();
        pinger.requeue(payload);
        assert_eq!(pinger.next_queued(), Some(first.to_be_bytes()));
        assert_eq!(pinger.next_queued(), Some(second.to_be_bytes()));
    }
}
