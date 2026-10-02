//! Owner-side order of joins, when the server reports Commits settled (`group_commit_gate`).
//!
//! The owner sends a join's Commit at once and holds the joiner's Welcome until the server
//! reports that Commit settled. One join is in flight at a time: a KeyPackage that arrives while
//! a Welcome is held waits its turn, because its Commit would reach the held joiner before that
//! joiner's Welcome, and a joiner ignores every Commit until its Welcome is applied.
//!
//! For the same reason, a Commit the owner makes for anything else (a kick, a demotion) first
//! releases the held Welcome: the joiner must have it before that Commit. That join then does
//! not wait for its Commit to settle, and a member still sealing at the old epoch can lose the
//! joiner a message, which the joiner sees as `MessageDropped`. The queued joins resume once the
//! other Commit settles.

use crate::proto::remote::Ticket;
use std::collections::VecDeque;

/// A joiner's Welcome, held until the Commit for `epoch` settles.
pub struct HeldWelcome {
    /// The epoch the join's Commit advanced the group into
    pub epoch: u64,
    /// The joiner
    pub joiner_cid: u64,
    /// The serialized Welcome
    pub welcome: Vec<u8>,
    /// The joiner's sealed hierarchy assignment, sent just before the Welcome
    pub assignment: Option<Vec<u8>>,
    /// The ticket of the joiner's KeyPackage
    pub ticket: Ticket,
}

/// A KeyPackage waiting for the join before it.
pub struct QueuedKeyPackage {
    /// The joiner
    pub joiner_cid: u64,
    /// The serialized KeyPackage
    pub key_package: Vec<u8>,
    /// The ticket it arrived with
    pub ticket: Ticket,
}

/// The join in flight, and the KeyPackages behind it.
#[derive(Default)]
pub struct JoinQueue {
    held: Option<HeldWelcome>,
    waiting: VecDeque<QueuedKeyPackage>,
}

impl JoinQueue {
    /// Queues `key_package` behind every join before it.
    pub fn enqueue(&mut self, key_package: QueuedKeyPackage) {
        self.waiting.push_back(key_package);
    }

    /// Holds `welcome` until its Commit settles.
    pub fn hold(&mut self, welcome: HeldWelcome) {
        debug_assert!(self.held.is_none(), "one join in flight at a time");
        self.held = Some(welcome);
    }

    /// The Commit for `epoch` settled: the Welcome it held, if any.
    pub fn settled(&mut self, epoch: u64) -> Option<HeldWelcome> {
        if self.held.as_ref()?.epoch == epoch {
            self.held.take()
        } else {
            None
        }
    }

    /// Another Commit is about to be sent: the Welcome to release before it, if any.
    pub fn flush(&mut self) -> Option<HeldWelcome> {
        self.held.take()
    }

    /// The next KeyPackage to add, when no Welcome is held.
    pub fn next(&mut self) -> Option<QueuedKeyPackage> {
        if self.held.is_some() {
            return None;
        }
        self.waiting.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(joiner_cid: u64) -> QueuedKeyPackage {
        QueuedKeyPackage {
            joiner_cid,
            key_package: vec![joiner_cid as u8],
            ticket: Ticket(joiner_cid as u128),
        }
    }

    fn welcome(epoch: u64, joiner_cid: u64) -> HeldWelcome {
        HeldWelcome {
            epoch,
            joiner_cid,
            welcome: vec![],
            assignment: None,
            ticket: Ticket(0),
        }
    }

    #[test]
    fn a_join_waits_for_the_one_in_flight() {
        let mut queue = JoinQueue::default();
        queue.enqueue(kp(2));
        assert_eq!(
            queue.next().map(|k| k.joiner_cid),
            Some(2),
            "nothing in flight"
        );
        queue.hold(welcome(1, 2));
        queue.enqueue(kp(3));
        assert!(queue.next().is_none(), "C waits until B's Commit settles");

        assert!(queue.settled(0).is_none(), "another epoch releases nothing");
        assert_eq!(queue.settled(1).map(|w| w.joiner_cid), Some(2));
        assert_eq!(queue.next().map(|k| k.joiner_cid), Some(3));
        assert!(queue.next().is_none());
    }

    #[test]
    fn another_commit_releases_the_held_welcome_and_joins_resume_when_it_settles() {
        let mut queue = JoinQueue::default();
        queue.hold(welcome(1, 2));
        queue.enqueue(kp(3));

        assert_eq!(queue.flush().map(|w| w.joiner_cid), Some(2));
        queue.enqueue(kp(4));
        assert!(
            queue.settled(1).is_none(),
            "the released Welcome is not released twice"
        );
        assert_eq!(queue.next().map(|k| k.joiner_cid), Some(3));
        assert_eq!(queue.next().map(|k| k.joiner_cid), Some(4));
    }
}
