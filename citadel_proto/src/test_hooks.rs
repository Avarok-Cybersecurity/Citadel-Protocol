//! Test-only hooks into the group protocol (feature `localhost-testing`; absent from any other
//! build).
//!
//! A race between two nodes is reached only by chance from the outside. These hooks hold a node
//! at the point the race turns on, so an integration test can drive the interleaving it means to
//! test and get the same outcome on every run.
//!
//! State is process-global and keyed by session cid, which is unique per registration; nextest
//! runs each test in its own process.

use citadel_io::tokio::sync::{mpsc, watch};
use citadel_types::proto::MessageGroupKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, OnceLock};

struct Hold {
    arrived: watch::Sender<bool>,
    released: watch::Receiver<bool>,
    applied: watch::Sender<bool>,
}

fn lock<T>(cell: &'static OnceLock<Mutex<T>>, init: fn() -> T) -> MutexGuard<'static, T> {
    cell.get_or_init(|| Mutex::new(init()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

static HOLDS: OnceLock<Mutex<HashMap<u64, Hold>>> = OnceLock::new();
static GATE_OBSERVERS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<CommitGateOpened>>>> =
    OnceLock::new();

/// Holds every group `Commit` the client session `session_cid` receives, before it is applied,
/// until the returned handle is released or dropped.
pub fn hold_inbound_commits(session_cid: u64) -> CommitHold {
    let (arrived_tx, arrived_rx) = watch::channel(false);
    let (release_tx, release_rx) = watch::channel(false);
    let (applied_tx, applied_rx) = watch::channel(false);
    let hold = Hold {
        arrived: arrived_tx,
        released: release_rx,
        applied: applied_tx,
    };
    let _ = lock(&HOLDS, HashMap::new).insert(session_cid, hold);
    CommitHold {
        session_cid,
        arrived: arrived_rx,
        release: release_tx,
        applied: applied_rx,
    }
}

/// A hold placed by [`hold_inbound_commits`]. Dropping it releases the session.
pub struct CommitHold {
    session_cid: u64,
    arrived: watch::Receiver<bool>,
    release: watch::Sender<bool>,
    applied: watch::Receiver<bool>,
}

impl CommitHold {
    /// Resolves once a Commit has reached the session and is being held.
    pub async fn arrived(&mut self) {
        let _ = self.arrived.wait_for(|arrived| *arrived).await;
    }

    /// Lets the held Commit, and any later one, be applied, and resolves once the session has
    /// handled it: anything the session seals from then on is at the new epoch.
    pub async fn release(mut self) {
        let _ = self.release.send(true);
        let _ = self.applied.wait_for(|applied| *applied).await;
    }
}

impl Drop for CommitHold {
    fn drop(&mut self) {
        let _ = lock(&HOLDS, HashMap::new).remove(&self.session_cid);
        let _ = self.release.send(true);
    }
}

/// Called by a client session as a Commit arrives, before it is applied.
pub(crate) async fn inbound_commit(session_cid: u64) {
    let mut released = {
        let holds = lock(&HOLDS, HashMap::new);
        let Some(hold) = holds.get(&session_cid) else {
            return;
        };
        let _ = hold.arrived.send(true);
        hold.released.clone()
    };
    let _ = released.wait_for(|released| *released).await;
}

/// Called by a client session once it has handled a Commit that was held.
pub(crate) fn commit_applied(session_cid: u64) {
    if let Some(hold) = lock(&HOLDS, HashMap::new).get(&session_cid) {
        let _ = hold.applied.send(true);
    }
}

/// The server began waiting for members to apply the owner's Commit for `epoch`.
#[derive(Debug, Clone)]
pub struct CommitGateOpened {
    /// The group
    pub key: MessageGroupKey,
    /// The epoch the Commit advances the group into
    pub epoch: u64,
    /// The members the server waits on
    pub awaiting: Vec<u64>,
}

/// Every [`CommitGateOpened`] in this process from now on.
pub fn observe_commit_gates() -> mpsc::UnboundedReceiver<CommitGateOpened> {
    let (tx, rx) = mpsc::unbounded_channel();
    lock(&GATE_OBSERVERS, Vec::new).push(tx);
    rx
}

/// Called by the server when it opens a gate.
#[allow(dead_code)]
pub(crate) fn commit_gate_opened(key: MessageGroupKey, epoch: u64, awaiting: &HashSet<u64>) {
    let opened = CommitGateOpened {
        key,
        epoch,
        awaiting: awaiting.iter().copied().collect(),
    };
    lock(&GATE_OBSERVERS, Vec::new).retain(|tx| tx.send(opened.clone()).is_ok());
}
