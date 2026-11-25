//! Test-only hooks into a replay group (see `test_hooks`): the server's replay of a returning
//! member, turn by turn, and a member's fetches of a gap.

use super::lock;
use citadel_io::tokio::sync::{mpsc, watch};
use citadel_types::proto::MessageGroupKey;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static TURN_OBSERVERS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<ReplayTurn>>>> = OnceLock::new();
static TURN_PAUSE: OnceLock<Mutex<Option<watch::Receiver<bool>>>> = OnceLock::new();
static SKIPS: OnceLock<Mutex<HashMap<u64, (usize, usize)>>> = OnceLock::new();
static GAP_FETCHES: OnceLock<Mutex<HashMap<MessageGroupKey, usize>>> = OnceLock::new();

/// One turn of a replay a server finished, with the group order lock released.
#[derive(Debug, Clone)]
pub struct ReplayTurn {
    pub key: MessageGroupKey,
    /// How many positions the turn sent.
    pub sent: usize,
}

/// Every replay turn a server in this process finishes, from now on.
pub fn observe_replay_turns() -> mpsc::UnboundedReceiver<ReplayTurn> {
    let (tx, rx) = mpsc::unbounded_channel();
    lock(&TURN_OBSERVERS, Vec::new).push(tx);
    rx
}

/// Holds every server of this process between replay turns, the lock released, until the
/// returned handle is released or dropped.
pub fn pause_replay_turns() -> PausedTurns {
    let (release, released) = watch::channel(false);
    *lock(&TURN_PAUSE, || None) = Some(released);
    PausedTurns { release }
}

/// A pause placed by [`pause_replay_turns`].
pub struct PausedTurns {
    release: watch::Sender<bool>,
}

impl PausedTurns {
    /// Lets every held replay go on.
    pub fn release(&self) {
        let _ = self.release.send(true);
    }
}

impl Drop for PausedTurns {
    fn drop(&mut self) {
        self.release();
        *lock(&TURN_PAUSE, || None) = None;
    }
}

/// Called by the server between two turns of a replay of `key`, the lock released.
pub(crate) async fn group_replay_turn(key: MessageGroupKey, sent: usize) {
    lock(&TURN_OBSERVERS, Vec::new).retain(|tx| tx.send(ReplayTurn { key, sent }).is_ok());
    let paused = lock(&TURN_PAUSE, || None).clone();
    if let Some(mut released) = paused {
        let _ = released.wait_for(|released| *released).await;
    }
}

/// How many gaps of `key` members in this process have fetched.
pub fn gap_fetches(key: MessageGroupKey) -> usize {
    lock(&GAP_FETCHES, HashMap::new)
        .get(&key)
        .copied()
        .unwrap_or_default()
}

/// Called by a member as it asks the server for a gap of `key`.
pub(crate) fn group_gap_fetched(key: MessageGroupKey) {
    *lock(&GAP_FETCHES, HashMap::new).entry(key).or_default() += 1;
}

/// Makes the server leave out the `nth` (from 1) positioned group message it fans out to
/// `member`, as if the member's stream lost it, until the returned guard drops.
pub fn skip_group_message_to(member: u64, nth: usize) -> SkippedMessage {
    let _ = lock(&SKIPS, HashMap::new).insert(member, (nth, 0));
    SkippedMessage { member }
}

/// A skip placed by [`skip_group_message_to`].
pub struct SkippedMessage {
    member: u64,
}

impl Drop for SkippedMessage {
    fn drop(&mut self) {
        let _ = lock(&SKIPS, HashMap::new).remove(&self.member);
    }
}

/// Called by the server for each member it fans `frame` out to: whether to leave it out.
pub(crate) fn skips_group_frame(
    member: u64,
    frame: &crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast,
) -> bool {
    use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
    let GroupBroadcast::Ordered { frame, .. } = frame else {
        return false;
    };
    if !matches!(**frame, GroupBroadcast::Message { .. }) {
        return false;
    }
    let mut skips = lock(&SKIPS, HashMap::new);
    let Some((nth, seen)) = skips.get_mut(&member) else {
        return false;
    };
    *seen += 1;
    *seen == *nth
}
