//! Bounded memory of outbound groups that finished, so a late wave ack for one
//! can be told apart from an ack for a group this node never sent.

use super::GroupKey;
use std::collections::{HashSet, VecDeque};

/// Large enough to cover the acks still in flight behind a completed group;
/// small enough that a long transfer does not grow it without bound.
const CAPACITY: usize = 4096;

#[derive(Default)]
pub(crate) struct CompletedGroups {
    order: VecDeque<GroupKey>,
    members: HashSet<GroupKey>,
}

impl CompletedGroups {
    pub(crate) fn record(&mut self, key: GroupKey) {
        if !self.members.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                let _ = self.members.remove(&oldest);
            }
        }
    }

    pub(crate) fn contains(&self, key: &GroupKey) -> bool {
        self.members.contains(key)
    }

    /// Why an ack names a group that has no transmitter. Acks travel on more
    /// than one stream, so the final wave ack can complete and free a group
    /// before its header ack, or a trailing wave ack, is read.
    pub(crate) fn orphan_ack(&self, key: &GroupKey) -> OrphanAck {
        if self.contains(key) {
            OrphanAck::GroupCompleted
        } else {
            OrphanAck::GroupUnknown
        }
    }

    pub(crate) fn note_orphan_ack(&self, ack: &str, key: &GroupKey) {
        match self.orphan_ack(key) {
            OrphanAck::GroupCompleted => {
                log::trace!(target: "citadel", "Late {ack} ack for {key:?}: the group already completed")
            }
            OrphanAck::GroupUnknown => {
                log::warn!(target: "citadel", "{ack} ack for {key:?} does not map to a transmitter container")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OrphanAck {
    GroupCompleted,
    GroupUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(group_id: u64) -> GroupKey {
        GroupKey::new(1, group_id, citadel_types::proto::ObjectId(0))
    }

    #[test]
    fn a_recorded_group_is_remembered_and_an_unknown_one_is_not() {
        let mut done = CompletedGroups::default();
        done.record(key(7));
        assert!(done.contains(&key(7)));
        // negative control: a group never recorded must not read as completed,
        // or the warn for a truly unknown group would be silenced too.
        assert!(!done.contains(&key(8)));
    }

    #[test]
    fn an_ack_for_a_completed_group_is_told_apart_from_an_unknown_one() {
        let mut done = CompletedGroups::default();
        done.record(key(7));
        assert_eq!(done.orphan_ack(&key(7)), OrphanAck::GroupCompleted);
        assert_eq!(done.orphan_ack(&key(8)), OrphanAck::GroupUnknown);
    }

    #[test]
    fn memory_is_bounded_and_forgets_the_oldest_first() {
        let mut done = CompletedGroups::default();
        for id in 0..(CAPACITY as u64 + 10) {
            done.record(key(id));
        }
        assert!(!done.contains(&key(0)));
        assert!(done.contains(&key(CAPACITY as u64 + 9)));
        assert_eq!(done.members.len(), CAPACITY);
    }
}
