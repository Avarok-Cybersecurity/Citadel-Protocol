//! How many of a session's group messages may be on the wire unanswered.
//!
//! The server handles one session's group broadcasts in the order they arrived (`group_lane`),
//! and a member's acknowledgement of a Commit must come after every message it sealed at the
//! epoch the Commit leaves. Without a limit on the sender, the messages queued ahead of that
//! acknowledgement grew with the sender's rate, and a joiner's Welcome, which waits for it, waited
//! with them. The window paces each session's group messages by the server's answers instead.

use citadel_io::tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use std::sync::Arc;

/// The most group messages one session may have written to the server and not yet had answered.
///
/// **The bound it gives.** A member's acknowledgement of a Commit is handled at the server after
/// at most this many of that member's own group messages, and the relayed Commit is handled at
/// the member after at most this many answers. A join therefore waits on at most this many
/// messages per member, however fast a member sends.
///
/// **Why 32.** The server pulls at most 64 packets of one session off the wire at a time
/// (`INBOUND_CONCURRENCY_LIMIT`). With at most 32 group messages in flight, a session's
/// acknowledgement fits in the same pull as every message ahead of it, with half the pull left
/// for the session's other packets. The limit is per session, so several sessions sending at once each have their own 32,
/// and the server's work grows with the number of senders, not with any one sender's rate.
///
/// **What it costs.** A session sustains at most 32 group messages per answer round trip: about
/// 320 a second at a 100 ms round trip, and far more on a short link. A burst of N messages
/// beyond the first 32 waits about `ceil((N - 32) / 32)` further round trips, so a sender with
/// many small operations should put several in one message.
///
/// **Why per session, not per group.** The queue it bounds is the server's, and the server keeps
/// one order per session across all of that session's groups. A per-group window would let a
/// member in many groups put many windows ahead of one acknowledgement. The cost is that a
/// session whose window is full waits to send to any of its groups. Credits are handed out in the
/// order senders asked for them, whichever group they send to, so no group's sender is passed over.
pub(crate) const GROUP_SEND_WINDOW: usize = 32;

/// The session ended: no answer will come, so no credit will be returned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WindowClosed;

/// One session's window.
pub(crate) struct SendWindow {
    credits: Arc<Semaphore>,
    in_flight: citadel_io::Mutex<usize>,
}

/// A place in the window, held by a message not yet written. Dropped unwritten, it returns its
/// place; written, it stays taken until the server's answer.
pub(crate) struct Credit {
    window: Arc<SendWindow>,
    permit: OwnedSemaphorePermit,
}

impl SendWindow {
    /// A window of `size` places.
    pub(crate) fn new(size: usize) -> Arc<Self> {
        Arc::new(Self {
            credits: Arc::new(Semaphore::new(size)),
            in_flight: citadel_io::Mutex::new(0),
        })
    }

    /// A place, once one is free. Places go to callers in the order they asked. Dropping the
    /// returned future gives back nothing, as it took nothing.
    pub(crate) async fn take(self: &Arc<Self>) -> Result<Credit, WindowClosed> {
        let permit = self
            .credits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WindowClosed)?;
        Ok(self.credit(permit))
    }

    /// A place for a message `session_cid` sends, once one is free.
    #[cfg_attr(not(feature = "localhost-testing"), allow(unused_variables))]
    pub(crate) async fn place(self: &Arc<Self>, session_cid: u64) -> Result<Credit, WindowClosed> {
        if let Some(credit) = self.try_take()? {
            return Ok(credit);
        }
        #[cfg(feature = "localhost-testing")]
        crate::test_hooks::group_send_waits(session_cid);
        self.take().await
    }

    /// A place if one is free now, without waiting.
    pub(crate) fn try_take(self: &Arc<Self>) -> Result<Option<Credit>, WindowClosed> {
        match self.credits.clone().try_acquire_owned() {
            Ok(permit) => Ok(Some(self.credit(permit))),
            Err(TryAcquireError::NoPermits) => Ok(None),
            Err(TryAcquireError::Closed) => Err(WindowClosed),
        }
    }

    /// The server answered a group message this session wrote: its place is free. An answer with
    /// no written message counted against it frees nothing, so the window never grows past its
    /// size. Returns whether a place was freed.
    pub(crate) fn answered(&self) -> bool {
        let mut in_flight = self.in_flight.lock();
        if *in_flight == 0 {
            log::warn!(target: "citadel", "A group message answer arrived with none unanswered");
            return false;
        }
        *in_flight -= 1;
        self.credits.add_permits(1);
        true
    }

    /// The session ended. Every caller waiting for a place, and every later one, is refused.
    pub(crate) fn close(&self) {
        self.credits.close();
    }

    #[cfg(test)]
    pub(crate) fn free(&self) -> usize {
        self.credits.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn unanswered(&self) -> usize {
        *self.in_flight.lock()
    }

    fn credit(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> Credit {
        Credit {
            window: self.clone(),
            permit,
        }
    }
}

impl std::fmt::Debug for Credit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credit")
    }
}

impl Credit {
    /// The message is about to be written: its place stays taken until the server answers. It is
    /// counted before the write, so an answer can never arrive ahead of its own count.
    pub(crate) fn written(self) {
        let Credit { window, permit } = self;
        let mut in_flight = window.in_flight.lock();
        permit.forget();
        *in_flight += 1;
    }
}

#[cfg(test)]
#[path = "group_send_window_tests.rs"]
mod tests;
