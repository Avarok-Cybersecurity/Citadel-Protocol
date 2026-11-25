//! Test-only hooks into a sender's file-transfer groups (see `test_hooks`): a group held right
//! after its header is handed to the stream, and each answer to a group header as it is read.
//!
//! Each is keyed by the cid a sender files its groups under: the peer's cid for a P2P transfer,
//! the sender's own session cid for a transfer to its server. An answer's header names the same
//! cid, so both ends of a test agree on it.

use super::lock;
use citadel_io::tokio::sync::{mpsc, watch};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

struct HeaderSentState {
    sent: watch::Sender<bool>,
    released: watch::Receiver<bool>,
}

static HEADER_HOLDS: OnceLock<Mutex<HashMap<u64, HeaderSentState>>> = OnceLock::new();
static HEADER_ACK_OBSERVERS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<GroupHeaderAckRead>>>> =
    OnceLock::new();

/// Holds the next group filed under `key_cid` once its header has been handed to the stream,
/// before the sender goes on, until the returned handle is released or dropped.
pub fn hold_group_header_sent(key_cid: u64) -> GroupHeaderHold {
    let (sent, sent_rx) = watch::channel(false);
    let (release, released) = watch::channel(false);
    let _ = lock(&HEADER_HOLDS, HashMap::new).insert(key_cid, HeaderSentState { sent, released });
    GroupHeaderHold {
        key_cid,
        sent: sent_rx,
        release,
    }
}

/// A hold placed by [`hold_group_header_sent`].
pub struct GroupHeaderHold {
    key_cid: u64,
    sent: watch::Receiver<bool>,
    release: watch::Sender<bool>,
}

impl GroupHeaderHold {
    /// Waits until the held group's header has been handed to the stream.
    pub async fn sent(&mut self) {
        let _ = self.sent.wait_for(|sent| *sent).await;
    }

    /// Lets the held sender go on.
    pub fn release(&self) {
        let _ = self.release.send(true);
    }
}

impl Drop for GroupHeaderHold {
    fn drop(&mut self) {
        self.release();
        let _ = lock(&HEADER_HOLDS, HashMap::new).remove(&self.key_cid);
    }
}

/// Called by a sender right after it hands the header of a group filed under `key_cid` to the
/// stream.
pub(crate) async fn group_header_sent(key_cid: u64) {
    let Some(mut released) = lock(&HEADER_HOLDS, HashMap::new)
        .remove(&key_cid)
        .map(|hold| {
            let _ = hold.sent.send(true);
            hold.released
        })
    else {
        return;
    };
    let _ = released.wait_for(|released| *released).await;
}

/// What an answer to a group header found when the sender read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAckFound {
    /// The transmitter of the group it answers.
    ItsTransmitter,
    /// No transmitter: its group had already completed.
    AfterItsGroupCompleted,
    /// No transmitter, and no record of the group: the branch that logs "does not map to a
    /// transmitter container".
    NoTransmitter,
}

/// One answer to a group header, as the sender read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupHeaderAckRead {
    /// The cid the answered group is filed under.
    pub key_cid: u64,
    /// What it found.
    pub found: HeaderAckFound,
}

/// Each answer to a group header a sender of this process reads, from now on.
pub fn observe_group_header_acks() -> mpsc::UnboundedReceiver<GroupHeaderAckRead> {
    let (tx, rx) = mpsc::unbounded_channel();
    lock(&HEADER_ACK_OBSERVERS, Vec::new).push(tx);
    rx
}

/// Called by a sender as it reads an answer to the header of a group filed under `key_cid`.
pub(crate) fn group_header_ack_read(key_cid: u64, found: HeaderAckFound) {
    let read = GroupHeaderAckRead { key_cid, found };
    lock(&HEADER_ACK_OBSERVERS, Vec::new).retain(|observer| observer.send(read).is_ok());
}
