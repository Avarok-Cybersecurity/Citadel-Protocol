//! The owner each of this client's group channels acts under (see `peer::group_owner`).

use super::StateContainerInner;
use crate::proto::peer::group_owner::GroupOwner;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

impl<R: Ratchet> StateContainerInner<R> {
    /// The cell a channel for `key` opening now shares with this session, naming `owner`.
    pub(super) fn open_group_owner(&mut self, key: MessageGroupKey, owner: u64) -> GroupOwner {
        let cell = self
            .group_owners
            .entry(key)
            .or_insert_with(|| GroupOwner::new(owner))
            .clone();
        cell.set(Some(owner));
        cell
    }

    /// The server reported `owner` as `key`'s owner, or (`None`) this session left the group.
    pub(crate) fn record_group_owner(&mut self, key: MessageGroupKey, owner: Option<u64>) {
        match owner {
            Some(owner) => {
                if let Some(cell) = self.group_owners.get(&key) {
                    cell.set(Some(owner));
                }
            }
            None => {
                if let Some(cell) = self.group_owners.remove(&key) {
                    cell.set(None);
                }
            }
        }
    }
}
