//! Test-only hooks into a session's outbound queue (see `test_hooks`): a group send held after
//! it has its place in the queue and before it writes, and the moment a session that is
//! shutting down reads its queue empty with such a send still writing.

use super::lock;
use citadel_io::tokio::sync::{mpsc, watch};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

struct SendHoldState {
    reserved: watch::Sender<bool>,
    released: watch::Receiver<bool>,
}

static SEND_HOLDS: OnceLock<Mutex<HashMap<u64, SendHoldState>>> = OnceLock::new();
static DRAIN_OBSERVERS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<()>>>> = OnceLock::new();

/// Holds the next group send of `session_cid` once it has its place in the session's queue
/// and before it writes there, until the returned handle is released or dropped.
pub fn hold_group_send(session_cid: u64) -> SendHold {
    let (reserved, reserved_rx) = watch::channel(false);
    let (release, released) = watch::channel(false);
    let _ =
        lock(&SEND_HOLDS, HashMap::new).insert(session_cid, SendHoldState { reserved, released });
    SendHold {
        session_cid,
        reserved: reserved_rx,
        release,
    }
}

/// A hold placed by [`hold_group_send`].
pub struct SendHold {
    session_cid: u64,
    reserved: watch::Receiver<bool>,
    release: watch::Sender<bool>,
}

impl SendHold {
    /// Waits until the held send has its place in the queue.
    pub async fn reserved(&mut self) {
        let _ = self.reserved.wait_for(|reserved| *reserved).await;
    }

    /// Lets the held send write.
    pub fn release(&self) {
        let _ = self.release.send(true);
    }
}

impl Drop for SendHold {
    fn drop(&mut self) {
        self.release();
        let _ = lock(&SEND_HOLDS, HashMap::new).remove(&self.session_cid);
    }
}

/// Called by a group send of `session_cid` between taking its place in the queue and writing.
pub(crate) async fn group_send_reserved(session_cid: u64) {
    let Some(mut released) = lock(&SEND_HOLDS, HashMap::new)
        .remove(&session_cid)
        .map(|hold| {
            let _ = hold.reserved.send(true);
            hold.released
        })
    else {
        return;
    };
    let _ = released.wait_for(|released| *released).await;
}

/// Each time, from now on, a session of this process shutting down reads its closed queue empty
/// while a send that took its place is still writing.
pub fn observe_drain_waits() -> mpsc::UnboundedReceiver<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    lock(&DRAIN_OBSERVERS, Vec::new).push(tx);
    rx
}

/// Called by a closed queue's drain that reads it empty with a send still writing.
pub(crate) fn drain_waits_for_a_send() {
    lock(&DRAIN_OBSERVERS, Vec::new).retain(|tx| tx.send(()).is_ok());
}
