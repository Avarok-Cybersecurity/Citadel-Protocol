//! Event inboxes a prefab fills for an application that may never read them.
//!
//! A prefab cannot know whether its application will take an event receiver. Events go to an
//! [`InboxSender`]; the application takes the receiver from an [`InboxClaim`]. Until it does,
//! events wait in a backlog of at most [`UNCLAIMED_BACKLOG`], and are flushed to the receiver
//! when it is taken. An event that finds the backlog full, the receiver dropped, or every claim
//! handle dropped is disposed of at once by [`Unclaimed::dispose`]: a file offer is declined, so
//! its sender learns the answer, and a channel is closed.

use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::Mutex;
use citadel_proto::prelude::{NodeResult, ObjectTransferHandler, Ratchet};
use std::collections::VecDeque;
use std::sync::Arc;

/// How many events wait for a receiver nobody has taken yet. Enough for the events that arrive
/// between a connection's start and the application taking its receiver; beyond that, an
/// application that has not taken it is not reading it.
pub const UNCLAIMED_BACKLOG: usize = 64;

/// What happens to an event nobody will read.
pub trait Unclaimed {
    fn dispose(self);
}

impl Unclaimed for ObjectTransferHandler {
    fn dispose(mut self) {
        log::debug!(target: "citadel", "Declining an unclaimed transfer of {:?} from {}", self.metadata.name, self.source);
        // Fails only if the protocol already dropped its side, which then needs no answer.
        let _ = self.decline();
    }
}

impl<R: Ratchet> Unclaimed for NodeResult<R> {
    fn dispose(self) {
        match self {
            NodeResult::ObjectTransferHandle(offer) => offer.handle.dispose(),
            // Dropping the channel closes it, so the peer is not left writing into it.
            other => log::trace!(target: "citadel", "Dropping an unclaimed event: {other:?}"),
        }
    }
}

enum State<T> {
    Unclaimed(VecDeque<T>),
    Claimed(UnboundedSender<T>),
    Closed,
}

struct Shared<T> {
    state: Mutex<State<T>>,
}

/// The prefab's side of an inbox.
pub struct InboxSender<T: Unclaimed> {
    shared: Arc<Shared<T>>,
}

/// The application's side of an inbox; clones share one claim. When the last clone drops
/// unclaimed, the backlog is disposed of and so is every later event.
pub struct InboxClaim<T: Unclaimed> {
    guard: Arc<ClaimGuard<T>>,
}

struct ClaimGuard<T: Unclaimed> {
    shared: Arc<Shared<T>>,
}

/// A new inbox: the prefab keeps the sender, the application gets the claim.
pub fn inbox<T: Unclaimed>() -> (InboxSender<T>, InboxClaim<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State::Unclaimed(VecDeque::new())),
    });
    let claim = InboxClaim {
        guard: Arc::new(ClaimGuard {
            shared: shared.clone(),
        }),
    };
    (InboxSender { shared }, claim)
}

impl<T: Unclaimed> InboxSender<T> {
    /// Hands `item` to the receiver, or keeps it until one is taken, or disposes of it.
    pub fn deliver(&self, item: T) {
        let refused = {
            let mut state = self.shared.state.lock();
            match &mut *state {
                State::Claimed(tx) => tx.send(item).err().map(|returned| returned.0),
                State::Unclaimed(backlog) if backlog.len() < UNCLAIMED_BACKLOG => {
                    backlog.push_back(item);
                    None
                }
                State::Unclaimed(_) | State::Closed => Some(item),
            }
        };
        // Disposed of outside the lock: declining a transfer sends on its channel.
        if let Some(item) = refused {
            item.dispose();
        }
    }
}

impl<T: Unclaimed> InboxClaim<T> {
    /// The receiver, the first time only; it starts with every event kept until now.
    pub fn take(&self) -> Option<UnboundedReceiver<T>> {
        let mut state = self.guard.shared.state.lock();
        let State::Unclaimed(backlog) = &mut *state else {
            return None;
        };
        let (tx, rx) = unbounded_channel();
        for item in backlog.drain(..) {
            // The receiver is held here, so this cannot fail.
            let _ = tx.send(item);
        }
        *state = State::Claimed(tx);
        Some(rx)
    }
}

impl<T: Unclaimed> Clone for InboxClaim<T> {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
        }
    }
}

impl<T: Unclaimed> Drop for ClaimGuard<T> {
    fn drop(&mut self) {
        let backlog = {
            let mut state = self.shared.state.lock();
            match std::mem::replace(&mut *state, State::Closed) {
                State::Unclaimed(backlog) => backlog,
                // A taken receiver outlives its claim: put it back.
                claimed @ State::Claimed(_) => {
                    *state = claimed;
                    VecDeque::new()
                }
                State::Closed => VecDeque::new(),
            }
        };
        backlog.into_iter().for_each(Unclaimed::dispose);
    }
}

#[cfg(test)]
#[path = "inbox_tests.rs"]
mod tests;
