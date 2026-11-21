//! A [`GroupCgkaState`] written out for the node's account store, and read back (see
//! `group_state_store`). Only a flat group's state is kept: a command hierarchy's rank table
//! lives with its owner's session, and such a group does not outlive it.

use super::{fresh_secret, ser_err, GroupCgkaState};
use crate::error::NetworkError;
use citadel_treekem::GroupState;
use citadel_types::proto::GroupHierarchyMode;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize)]
struct Stored {
    tree: u64,
    is_owner: bool,
    own_leaf_secret: [u8; 32],
    group: Vec<u8>,
}

impl GroupCgkaState {
    /// The state as the account store keeps it; `None` for one that is not kept (a join still
    /// waiting for its Welcome, or a command hierarchy).
    pub fn export(&self) -> Result<Option<Zeroizing<Vec<u8>>>, NetworkError> {
        let Some(group) = self.group.as_ref().filter(|_| self.is_flat()) else {
            return Ok(None);
        };
        let mut stored = Stored {
            tree: self.tree,
            is_owner: self.is_owner,
            own_leaf_secret: self.own_leaf_secret,
            group: group.export()?.to_vec(),
        };
        let bytes = stored
            .serialize_to_vector()
            .map_err(|_| ser_err("stored_group_state"));
        stored.zeroize();
        bytes.map(|bytes| Some(Zeroizing::new(bytes)))
    }

    /// A state written by [`Self::export`]. It sends under a fresh incarnation, so nothing it sent
    /// before it was written is ever sealed again under the same key.
    pub fn import(bytes: &[u8]) -> Result<Self, NetworkError> {
        let mut stored =
            Stored::deserialize_from_vector(bytes).map_err(|_| ser_err("stored_group_state"))?;
        let mut incarnation = [0u8; 8];
        incarnation.copy_from_slice(&fresh_secret()[..8]);
        let incarnation = u64::from_be_bytes(incarnation).max(1);
        let group = GroupState::import(&stored.group, incarnation);
        let state = group.map(|group| Self {
            group: Some(group),
            own_leaf_secret: stored.own_leaf_secret,
            is_owner: stored.is_owner,
            hierarchy: GroupHierarchyMode::Flat,
            hierarchy_self: None,
            pending_ranks: Default::default(),
            joins: Default::default(),
            tree: stored.tree,
            saved: None,
            opens: 0,
        });
        stored.zeroize();
        Ok(state?)
    }

    /// Whether the state changed in a way worth writing since it was last written: its epoch or
    /// membership, or another [`OPENS_PER_WRITE`] messages opened (their replay record).
    pub(crate) fn take_unsaved(&mut self) -> bool {
        let Some(group) = self.group.as_ref() else {
            return false;
        };
        let mark = (self.tree, group.epoch, self.opens / OPENS_PER_WRITE);
        if self.saved == Some(mark) {
            return false;
        }
        self.saved = Some(mark);
        true
    }
}

/// How many opened messages go unrecorded at most before the state is written again.
pub(crate) const OPENS_PER_WRITE: u64 = 16;
