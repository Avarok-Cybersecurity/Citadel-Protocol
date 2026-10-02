//! Server-side wait for a group's members to apply the owner's latest Commit.
//!
//! A member seals each message at the epoch it holds. Until it applies the owner's Commit for a
//! join it seals at the epoch before the join, which the joiner can never read (join forward
//! secrecy). So the owner holds the joiner's Welcome until the server reports that the Commit
//! has *settled*: no member that could still seal at the old epoch is left.
//!
//! The rule, for the owner's Commit for `epoch` (owner and server at `GROUP_COMMIT_ACK_SINCE` or
//! later):
//! - The server waits on every group member, other than the owner, to which it delivered the
//!   Commit directly and whose session is at `GROUP_COMMIT_ACK_SINCE` or later. A member that
//!   is offline gets the Commit by mailbox and is not waited on: a session that returns holds no
//!   group state, so it seals nothing until it has rejoined at the current epoch. An older member
//!   cannot acknowledge and is not waited on either; it can still lose a joiner a message, which
//!   the joiner's application then sees as `MessageDropped`.
//! - A member leaves the wait when it acknowledges the Commit (`CommitApplied`), when its
//!   session ends, or when it is removed from the group. It acknowledges once it has processed
//!   the Commit, whether or not the Commit applied to it (a joiner awaiting its own Welcome holds
//!   nothing to seal with); a member whose processing fails ends its session.
//! - The wait settles when no member is left in it, at once if there was none. A later Commit
//!   for the same group replaces it.
//!
//! No timer bounds the wait. It lasts as long as a member stays connected without processing a
//! Commit, and only the joiner's Welcome waits with it: the group's traffic does not.
//!
//! The state here is I/O-free; `group_commit_relay` sends what it decides.

use citadel_types::proto::MessageGroupKey;
use std::collections::{HashMap, HashSet};

/// The owner's Commit for `epoch` in `key` has settled: tell the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    /// The group
    pub key: MessageGroupKey,
    /// The epoch the settled Commit advanced the group into
    pub epoch: u64,
}

struct Gate {
    epoch: u64,
    awaiting: HashSet<u64>,
}

/// One wait per group, for the owner's latest Commit.
#[derive(Default)]
pub struct CommitGates {
    gates: HashMap<MessageGroupKey, Gate>,
}

impl CommitGates {
    /// Wait on `awaiting` to apply the Commit for `epoch`, replacing any earlier wait for `key`.
    /// Settled at once when there is nobody to wait on.
    pub fn open(
        &mut self,
        key: MessageGroupKey,
        epoch: u64,
        awaiting: HashSet<u64>,
    ) -> Option<Settled> {
        let _ = self.gates.insert(key, Gate { epoch, awaiting });
        self.settle_if_done(key)
    }

    /// `member` has processed the Commit for `epoch`.
    pub fn applied(&mut self, key: MessageGroupKey, epoch: u64, member: u64) -> Option<Settled> {
        self.remove_from(key, Some(epoch), &[member])
    }

    /// `members` did not receive the Commit for `epoch` directly.
    pub fn undelivered(
        &mut self,
        key: MessageGroupKey,
        epoch: u64,
        members: &[u64],
    ) -> Option<Settled> {
        self.remove_from(key, Some(epoch), members)
    }

    /// `members` were removed from `key`: they will apply no Commit of it.
    pub fn removed(&mut self, key: MessageGroupKey, members: &[u64]) -> Option<Settled> {
        self.remove_from(key, None, members)
    }

    /// `cid`'s session ended: it leaves every wait, and the waits of the groups it owns end
    /// unsettled, since there is no owner to tell.
    pub fn session_ended(&mut self, cid: u64) -> Vec<Settled> {
        self.gates.retain(|key, _| key.cid != cid);
        let keys: Vec<MessageGroupKey> = self
            .gates
            .iter_mut()
            .filter_map(|(key, gate)| gate.awaiting.remove(&cid).then_some(*key))
            .collect();
        keys.into_iter()
            .filter_map(|key| self.settle_if_done(key))
            .collect()
    }

    /// The group is gone.
    pub fn close(&mut self, key: MessageGroupKey) {
        let _ = self.gates.remove(&key);
    }

    fn remove_from(
        &mut self,
        key: MessageGroupKey,
        epoch: Option<u64>,
        members: &[u64],
    ) -> Option<Settled> {
        let gate = self.gates.get_mut(&key)?;
        if epoch.is_some_and(|epoch| epoch != gate.epoch) {
            return None;
        }
        let before = gate.awaiting.len();
        gate.awaiting.retain(|cid| !members.contains(cid));
        if gate.awaiting.len() == before {
            return None;
        }
        self.settle_if_done(key)
    }

    fn settle_if_done(&mut self, key: MessageGroupKey) -> Option<Settled> {
        let epoch = self
            .gates
            .get(&key)
            .filter(|gate| gate.awaiting.is_empty())?
            .epoch;
        let _ = self.gates.remove(&key);
        Some(Settled { key, epoch })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: MessageGroupKey = MessageGroupKey { cid: 1, mgid: 7 };

    fn set(cids: &[u64]) -> HashSet<u64> {
        cids.iter().copied().collect()
    }

    #[test]
    fn a_commit_nobody_must_apply_settles_at_once() {
        let mut gates = CommitGates::default();
        assert_eq!(
            gates.open(KEY, 3, set(&[])),
            Some(Settled { key: KEY, epoch: 3 })
        );
    }

    #[test]
    fn a_commit_settles_once_every_member_applied_it() {
        let mut gates = CommitGates::default();
        assert_eq!(gates.open(KEY, 3, set(&[2, 3])), None);
        assert_eq!(
            gates.applied(KEY, 3, 2),
            None,
            "member 3 has not applied it"
        );
        assert_eq!(
            gates.applied(KEY, 3, 2),
            None,
            "a repeated ack settles nothing"
        );
        assert_eq!(
            gates.applied(KEY, 3, 3),
            Some(Settled { key: KEY, epoch: 3 })
        );
        assert_eq!(
            gates.applied(KEY, 3, 3),
            None,
            "a settled gate settles once"
        );
    }

    #[test]
    fn an_ack_for_another_epoch_or_member_settles_nothing() {
        let mut gates = CommitGates::default();
        let _ = gates.open(KEY, 3, set(&[2]));
        assert_eq!(gates.applied(KEY, 2, 2), None);
        assert_eq!(gates.applied(KEY, 3, 9), None);
        assert_eq!(gates.undelivered(KEY, 4, &[2]), None);
        assert_eq!(
            gates.applied(KEY, 3, 2),
            Some(Settled { key: KEY, epoch: 3 })
        );
    }

    #[test]
    fn a_later_commit_replaces_the_wait() {
        let mut gates = CommitGates::default();
        let _ = gates.open(KEY, 3, set(&[2]));
        let _ = gates.open(KEY, 4, set(&[2]));
        assert_eq!(gates.applied(KEY, 3, 2), None);
        assert_eq!(
            gates.applied(KEY, 4, 2),
            Some(Settled { key: KEY, epoch: 4 })
        );
    }

    #[test]
    fn members_that_cannot_apply_it_leave_the_wait() {
        let mut gates = CommitGates::default();
        let _ = gates.open(KEY, 3, set(&[2, 3, 4]));
        assert_eq!(gates.undelivered(KEY, 3, &[2]), None);
        assert_eq!(gates.removed(KEY, &[3]), None);
        assert_eq!(gates.session_ended(4), vec![Settled { key: KEY, epoch: 3 }]);
    }

    #[test]
    fn an_owners_departure_ends_its_waits_unsettled() {
        let mut gates = CommitGates::default();
        let _ = gates.open(KEY, 3, set(&[2]));
        assert_eq!(gates.session_ended(KEY.cid), vec![]);
        assert_eq!(gates.applied(KEY, 3, 2), None);
    }

    #[test]
    fn a_closed_group_settles_nothing() {
        let mut gates = CommitGates::default();
        let _ = gates.open(KEY, 3, set(&[2]));
        gates.close(KEY);
        assert_eq!(gates.applied(KEY, 3, 2), None);
    }
}
