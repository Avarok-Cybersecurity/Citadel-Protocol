//! How many sessions a node still holds in memory.
//!
//! Every session takes a [`SessionHold`] when it is built and gives it back when its last handle
//! drops, so the count covers sessions that are connected, mid-handshake and still ending alike.
//! A session that has ended but is still counted is held by something that outlived it: a task,
//! a channel or a map entry. The node's shutdown waits on the same count.

use crate::proto::disconnect_tracker::DisconnectSignalTracker;
use citadel_io::tokio::sync::Notify;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// What a node still holds for its sessions, as counts: see `NodeRemote::session_footprint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFootprint {
    /// Sessions held in memory: connected, mid-handshake, or ended but not yet released.
    pub sessions: usize,
    /// Disconnect records kept for those sessions.
    pub disconnect_records: usize,
}

/// Where a [`SessionFootprint`] is read from.
#[derive(Clone, Default)]
pub(crate) struct FootprintSource {
    pub(crate) ledger: SessionLedger,
    pub(crate) disconnect_tracker: DisconnectSignalTracker,
}

impl FootprintSource {
    pub(crate) fn snapshot(&self) -> SessionFootprint {
        SessionFootprint {
            sessions: self.ledger.held(),
            disconnect_records: self.disconnect_tracker.records(),
        }
    }
}

/// The node-wide count of sessions held in memory.
#[derive(Clone, Default)]
pub(crate) struct SessionLedger {
    inner: Arc<LedgerInner>,
}

#[derive(Default)]
struct LedgerInner {
    held: AtomicUsize,
    released: Notify,
}

/// One session's place in the [`SessionLedger`], given back on drop.
pub(crate) struct SessionHold {
    inner: Arc<LedgerInner>,
}

impl SessionLedger {
    pub(crate) fn hold(&self) -> SessionHold {
        let _ = self.inner.held.fetch_add(1, Ordering::SeqCst);
        SessionHold {
            inner: self.inner.clone(),
        }
    }

    /// Sessions held right now.
    pub(crate) fn held(&self) -> usize {
        self.inner.held.load(Ordering::SeqCst)
    }

    /// Resolves once `still_held` returns false, re-checking it each time a session is released.
    pub(crate) async fn released_when(&self, still_held: impl Fn() -> bool) {
        loop {
            let released = self.inner.released.notified();
            citadel_io::tokio::pin!(released);
            // Registered before the check, so a release between the check and the await wakes it.
            let _ = released.as_mut().enable();
            if !still_held() {
                return;
            }
            released.await;
        }
    }
}

impl Drop for SessionHold {
    fn drop(&mut self) {
        let _ = self.inner.held.fetch_sub(1, Ordering::SeqCst);
        self.inner.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::time::Duration;

    #[test]
    fn a_hold_counts_until_it_is_dropped() {
        let ledger = SessionLedger::default();
        let first = ledger.hold();
        let second = ledger.hold();
        assert_eq!(ledger.held(), 2);
        drop(first);
        assert_eq!(ledger.held(), 1);
        drop(second);
        assert_eq!(ledger.held(), 0);
    }

    #[tokio::test]
    async fn waiting_ends_when_the_last_watched_hold_is_released() {
        let ledger = SessionLedger::default();
        let hold = ledger.hold();
        let watched = Arc::new(());
        let probe = Arc::downgrade(&watched);
        let waiting = {
            let ledger = ledger.clone();
            tokio::spawn(async move { ledger.released_when(|| probe.strong_count() > 0).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(watched);
        drop(hold);
        // An upper bound only: the release wakes the waiter at once.
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the waiter was not woken by the release")
            .unwrap();
    }
}
