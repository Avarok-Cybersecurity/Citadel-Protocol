//! Who owns a group once its owner leaves, and when a group ends.
//!
//! A group's owner is its creator until the owner leaves: it sends `LeaveRoom` for its own group,
//! or its account is deregistered. Ownership then passes to the remaining member with the highest
//! cid. A group lives until its owner closes it (`End`) or its last member leaves; a session
//! ending is not leaving (see `group_retention`), and no timer ends a group.
//!
//! The successor is a pure function of the member set ([`after_leave`]), decided and persisted
//! under the registry's write lock in the same critical section that removes the leaver. So two
//! leaves racing each other are applied one after the other, and a leave replayed (a member that
//! is no longer there) changes nothing: every order of the same leaves ends at the same owner.
//!
//! A command hierarchy's owner cannot hand the group on: its rank table lives only in the owner's
//! session. Its owner leaving ends the group, as its owner's session ending does.

use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};

/// What a member leaving does to its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Succession {
    /// The group goes on under the same owner.
    Stays,
    /// The owner left; this member owns the group now.
    PassesTo(u64),
    /// The group ends.
    Ends,
}

/// The successor among `members`: the one with the highest cid.
pub fn successor(members: &[u64]) -> Option<u64> {
    members.iter().copied().max()
}

/// What `leaver` leaving a group owned by `owner` does, with `remaining` the members left after it.
pub fn after_leave(owner: u64, leaver: u64, remaining: &[u64], flat: bool) -> Succession {
    match successor(remaining) {
        None => Succession::Ends,
        Some(_) if leaver != owner => Succession::Stays,
        Some(_) if !flat => Succession::Ends,
        Some(next) => Succession::PassesTo(next),
    }
}

/// The outcome of a leave, for the server to tell the members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leave {
    /// The leaver is not a member of the group here (or there is no such group).
    NotAMember,
    /// A member other than the owner left.
    Left { remaining: Vec<u64> },
    /// The owner left and `owner` owns the group now. `tree` is the group's tree generation.
    Transferred {
        owner: u64,
        previous: u64,
        tree: u64,
        remaining: Vec<u64>,
    },
    /// The group is gone. `remaining` are the members it ended under (none when the last left).
    Closed { remaining: Vec<u64> },
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// The recorded owner of `key`, if the group exists here.
    pub async fn group_owner(&self, key: MessageGroupKey) -> Option<u64> {
        let this = self.inner.read().await;
        Some(this.message_groups.get(&key.cid)?.get(&key.mgid)?.owner)
    }

    /// Removes `leaver` from `key` and, in the same critical section, records the group's next
    /// owner or removes the group, and persists the result.
    pub async fn leave_group(&self, key: MessageGroupKey, leaver: u64) -> Leave {
        let mut guard = self.inner.write().await;
        let this = &mut *guard;
        let Some(group) = this
            .message_groups
            .get_mut(&key.cid)
            .and_then(|groups| groups.get_mut(&key.mgid))
        else {
            return Leave::NotAMember;
        };
        if group.concurrent_peers.remove(&leaver).is_none() {
            return Leave::NotAMember;
        }
        let _ = group.resumed.remove(&leaver);
        let mut remaining: Vec<u64> = group.concurrent_peers.keys().copied().collect();
        remaining.sort_unstable();
        let flat = matches!(group.options.hierarchy, GroupHierarchyMode::Flat);
        let previous = group.owner;
        let leave = match after_leave(previous, leaver, &remaining, flat) {
            Succession::Stays => Leave::Left { remaining },
            Succession::PassesTo(owner) => {
                group.owner = owner;
                // A wait for the departed owner's Commit has nobody left to tell.
                this.commit_gates.close(key);
                let tree = group.tree;
                Leave::Transferred {
                    owner,
                    previous,
                    tree,
                    remaining,
                }
            }
            Succession::Ends => {
                let _ = this
                    .message_groups
                    .get_mut(&key.cid)
                    .and_then(|groups| groups.remove(&key.mgid));
                this.commit_gates.close(key);
                Leave::Closed { remaining }
            }
        };
        this.persist_group_or_log(key).await;
        leave
    }

    /// `leaver`'s account is gone: it leaves every group it is a member of.
    pub async fn leave_all_groups(&self, leaver: u64) -> Vec<(MessageGroupKey, Leave)> {
        let keys: Vec<MessageGroupKey> = {
            let this = self.inner.read().await;
            this.message_groups
                .iter()
                .flat_map(|(creator, groups)| {
                    groups
                        .iter()
                        .filter(|(_, group)| group.concurrent_peers.contains_key(&leaver))
                        .map(|(mgid, _)| MessageGroupKey {
                            cid: *creator,
                            mgid: *mgid,
                        })
                })
                .collect()
        };
        let mut left = Vec::with_capacity(keys.len());
        for key in keys {
            left.push((key, self.leave_group(key, leaver).await));
        }
        left
    }
}

#[cfg(test)]
#[path = "group_succession_tests.rs"]
mod tests;
