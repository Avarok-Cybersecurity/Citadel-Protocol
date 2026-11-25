//! Hooks on a session's group send window and on the order the server handles a member's
//! messages and its Commit acknowledgement in.

use super::lock;
use citadel_io::tokio::sync::{mpsc, watch};
use citadel_types::proto::MessageGroupKey;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static WAITS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<u64>>>> = OnceLock::new();
static WRITES: OnceLock<Mutex<Vec<mpsc::UnboundedSender<u64>>>> = OnceLock::new();
static RELAY_HOLDS: OnceLock<Mutex<HashMap<u64, watch::Receiver<bool>>>> = OnceLock::new();
static RELAYED: OnceLock<Mutex<HashMap<u64, usize>>> = OnceLock::new();
static ACKS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<CommitAcknowledged>>>> = OnceLock::new();

fn notify<T: Clone>(observers: &'static OnceLock<Mutex<Vec<mpsc::UnboundedSender<T>>>>, value: T) {
    lock(observers, Vec::new).retain(|tx| tx.send(value.clone()).is_ok());
}

fn observe<T>(
    observers: &'static OnceLock<Mutex<Vec<mpsc::UnboundedSender<T>>>>,
) -> mpsc::UnboundedReceiver<T> {
    let (tx, rx) = mpsc::unbounded_channel();
    lock(observers, Vec::new).push(tx);
    rx
}

/// How many group messages a session may have unanswered (`GROUP_SEND_WINDOW`).
pub fn group_send_window_size() -> usize {
    crate::proto::peer::group_send_window::GROUP_SEND_WINDOW
}

/// The cid of every session from now on that found its group send window full and waits for a
/// place.
pub fn observe_group_send_waits() -> mpsc::UnboundedReceiver<u64> {
    observe(&WAITS)
}

/// The cid of every session from now on that writes a group message to the server.
pub fn observe_group_message_writes() -> mpsc::UnboundedReceiver<u64> {
    observe(&WRITES)
}

pub(crate) fn group_send_waits(session_cid: u64) {
    notify(&WAITS, session_cid);
}

pub(crate) fn group_message_written(session_cid: u64) {
    notify(&WRITES, session_cid);
}

/// Holds the server's relay of every group message `sender` sends, and with it every group
/// broadcast after it from that session, until the returned handle is released or dropped.
pub fn hold_group_relays(sender: u64) -> RelayHold {
    let (release, released) = watch::channel(false);
    let _ = lock(&RELAY_HOLDS, HashMap::new).insert(sender, released);
    RelayHold { sender, release }
}

/// A hold placed by [`hold_group_relays`]. Dropping it releases the sender.
pub struct RelayHold {
    sender: u64,
    release: watch::Sender<bool>,
}

impl Drop for RelayHold {
    fn drop(&mut self) {
        let _ = lock(&RELAY_HOLDS, HashMap::new).remove(&self.sender);
        let _ = self.release.send(true);
    }
}

pub(crate) async fn relay_held(sender: u64) {
    let held = lock(&RELAY_HOLDS, HashMap::new).get(&sender).cloned();
    if let Some(mut released) = held {
        let _ = released.wait_for(|released| *released).await;
    }
}

pub(crate) fn relayed(sender: u64) {
    *lock(&RELAYED, HashMap::new).entry(sender).or_default() += 1;
}

/// The server handled a member's acknowledgement of a Commit.
#[derive(Debug, Clone)]
pub struct CommitAcknowledged {
    /// The group
    pub key: MessageGroupKey,
    /// The member that acknowledged it
    pub member: u64,
    /// The epoch the Commit moves the group to
    pub epoch: u64,
    /// How many of the member's group messages the server had relayed before it
    pub relayed_before: usize,
}

/// Every [`CommitAcknowledged`] in this process from now on.
pub fn observe_commit_acknowledgements() -> mpsc::UnboundedReceiver<CommitAcknowledged> {
    observe(&ACKS)
}

pub(crate) fn commit_acknowledged(key: MessageGroupKey, member: u64, epoch: u64) {
    let relayed_before = lock(&RELAYED, HashMap::new)
        .get(&member)
        .copied()
        .unwrap_or(0);
    notify(
        &ACKS,
        CommitAcknowledged {
            key,
            member,
            epoch,
            relayed_before,
        },
    );
}
