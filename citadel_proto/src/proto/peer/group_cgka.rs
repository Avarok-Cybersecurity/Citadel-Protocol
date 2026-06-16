//! Client-side coordinator for the post-quantum **TreeKEM CGKA** that backs zero-trust group
//! messaging. Each client holds one [`GroupCgkaState`] per group; the relay server only ever forwards
//! the opaque [`GroupBroadcast::KeyPackage`]/[`GroupBroadcast::Welcome`]/[`GroupBroadcast::Commit`]
//! payloads and the [`GroupBroadcast::Message`] ciphertext — it never holds a key or sees plaintext.
//!
//! The group **owner** (`key.cid`) is the sole committer (which matches the existing owner-only
//! Add/Kick/End permission model), so commits are produced and ordered by a single party and the
//! concurrent-commit linearization problem does not arise.
//!
//! This module is deliberately I/O-free: methods mutate in-memory CGKA state and return the bytes to
//! relay, and the caller (`group_broadcast.rs`) performs the packet send. That keeps the crypto state
//! machine unit-testable and avoids holding the `state_container` lock across an await.

use crate::error::NetworkError;
use citadel_io::{error, ErrorCode};
use citadel_treekem::{AppCiphertext, Commit, GroupState, KeyPackage, Welcome};
use citadel_types::proto::GroupHierarchyMode;
use citadel_user::serialization::SyncIO;

/// A 32-byte CGKA secret (leaf secret / path secret).
type Secret = [u8; 32];

/// One client's CGKA state for a single group.
pub struct GroupCgkaState {
    /// Synchronized ratchet-tree state. `None` for a joiner that has published its KeyPackage but not
    /// yet received its Welcome (so it cannot yet encrypt/decrypt).
    pub group: Option<GroupState>,
    /// This member's own leaf secret — kept private; it opens the Welcome and reproduces the leaf
    /// KEM keypair. Consumed into [`GroupState::create`] for the owner; retained by a joiner until its
    /// Welcome arrives.
    own_leaf_secret: Secret,
    /// Whether this member is the group owner (the sole committer).
    is_owner: bool,
    /// The group's hierarchy mode (carried for the DHE overlay; `Flat` is the ordinary path).
    #[allow(dead_code)]
    hierarchy: GroupHierarchyMode,
}

/// A fresh, cryptographically-random 32-byte secret (for leaf re-keys giving post-compromise security).
fn fresh_secret() -> Secret {
    use citadel_io::RngCore;
    let mut s = [0u8; 32];
    citadel_io::thread_rng().fill_bytes(&mut s);
    s
}

fn ser_err(context: &'static str) -> NetworkError {
    error!(ErrorCode::ProtoGroupCgkaSerialization, context)
}

impl GroupCgkaState {
    /// Found a new group as the owner (sole member, epoch 0).
    pub fn new_owner(cid: u64, hierarchy: GroupHierarchyMode) -> Result<Self, NetworkError> {
        let own_leaf_secret = fresh_secret();
        let kp = KeyPackage::generate(cid, &own_leaf_secret)?;
        let group = GroupState::create(kp.leaf, own_leaf_secret);
        Ok(Self {
            group: Some(group),
            own_leaf_secret,
            is_owner: true,
            hierarchy,
        })
    }

    /// Begin joining a group: generate a fresh leaf secret and the [`KeyPackage`] to publish to the
    /// owner. The group state stays `None` until the matching Welcome arrives.
    pub fn new_joiner(
        cid: u64,
        hierarchy: GroupHierarchyMode,
    ) -> Result<(Self, Vec<u8>), NetworkError> {
        let own_leaf_secret = fresh_secret();
        let kp = KeyPackage::generate(cid, &own_leaf_secret)?;
        let payload = kp
            .serialize_to_vector()
            .map_err(|_| ser_err("key_package"))?;
        Ok((
            Self {
                group: None,
                own_leaf_secret,
                is_owner: false,
                hierarchy,
            },
            payload,
        ))
    }

    /// Owner-only: incorporate a joiner's published `KeyPackage`, producing the `Welcome` (for the
    /// joiner) and the `Commit` (for the existing members). Returns `(welcome_bytes, commit_bytes,
    /// new_epoch)`.
    pub fn add_member(
        &mut self,
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, u64), NetworkError> {
        if !self.is_owner {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let kp = KeyPackage::deserialize_from_vector(key_package_bytes)
            .map_err(|_| ser_err("key_package"))?;
        let (commit, welcome) = group.add_member(&kp, fresh_secret())?;
        let epoch = group.epoch;
        let welcome_bytes = welcome
            .serialize_to_vector()
            .map_err(|_| ser_err("welcome"))?;
        let commit_bytes = commit
            .serialize_to_vector()
            .map_err(|_| ser_err("commit"))?;
        Ok((welcome_bytes, commit_bytes, epoch))
    }

    /// Owner-only: remove a member by leaf index, producing the `Commit` to broadcast. Returns
    /// `(commit_bytes, new_epoch)`. Re-keys the committer's path so the removed member's keys are dead
    /// in the new epoch (post-compromise security).
    pub fn remove_member(&mut self, leaf_index: u32) -> Result<(Vec<u8>, u64), NetworkError> {
        if !self.is_owner {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let commit = group.remove_member(leaf_index, fresh_secret())?;
        let epoch = group.epoch;
        let commit_bytes = commit
            .serialize_to_vector()
            .map_err(|_| ser_err("commit"))?;
        Ok((commit_bytes, epoch))
    }

    /// Owner-only: remove the member holding `cid` (no-op `Ok(None)` if it isn't a current member).
    pub fn remove_member_by_cid(
        &mut self,
        cid: u64,
    ) -> Result<Option<(Vec<u8>, u64)>, NetworkError> {
        if !self.is_owner {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        let leaf = self
            .group
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?
            .tree
            .leaf_index_of_cid(cid);
        match leaf {
            Some(leaf_index) => Ok(Some(self.remove_member(leaf_index)?)),
            None => Ok(None),
        }
    }

    /// Joiner: bootstrap the group state from a received `Welcome`.
    pub fn join(&mut self, welcome_bytes: &[u8]) -> Result<(), NetworkError> {
        let welcome =
            Welcome::deserialize_from_vector(welcome_bytes).map_err(|_| ser_err("welcome"))?;
        let group = GroupState::join_from_welcome(&welcome, self.own_leaf_secret)?;
        self.group = Some(group);
        Ok(())
    }

    /// Existing member: apply a `Commit` from the owner, gated on `commit_epoch`. A commit is applied
    /// only when it advances this member by exactly one epoch (`commit_epoch == current + 1`). A joiner
    /// that has not bootstrapped yet (group `None`), or one whose Welcome already encoded this commit
    /// (its own Add: `commit_epoch == current`), ignores it. Out-of-order future commits are dropped
    /// (the owner is the sole, in-order committer, so this only guards races, not the steady state).
    pub fn process_commit(
        &mut self,
        commit_bytes: &[u8],
        commit_epoch: u64,
    ) -> Result<(), NetworkError> {
        let Some(group) = self.group.as_mut() else {
            return Ok(());
        };
        if commit_epoch != group.epoch + 1 {
            return Ok(());
        }
        let commit =
            Commit::deserialize_from_vector(commit_bytes).map_err(|_| ser_err("commit"))?;
        group.process_commit(&commit)
    }

    /// Encrypt an outbound application message to the current epoch. Returns the serialized
    /// [`AppCiphertext`] the relay forwards verbatim.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let ct = group.encrypt_message(plaintext)?;
        ct.serialize_to_vector()
            .map_err(|_| ser_err("app_ciphertext"))
    }

    /// Decrypt an inbound application message under the current epoch.
    pub fn decrypt_message(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let ct = AppCiphertext::deserialize_from_vector(ciphertext)
            .map_err(|_| ser_err("app_ciphertext"))?;
        group.decrypt_message(&ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::MessageGroupKey;

    /// Owner founds a group, two joiners publish KeyPackages and bootstrap from Welcomes, and an
    /// application message round-trips E2E — mirroring the live relay flow without any network.
    #[test]
    fn owner_add_two_then_message_roundtrips() {
        let key = MessageGroupKey::new(1, 42);
        let mut owner = GroupCgkaState::new_owner(1, GroupHierarchyMode::Flat).unwrap();

        // B joins.
        let (mut b, kp_b) = GroupCgkaState::new_joiner(2, GroupHierarchyMode::Flat).unwrap();
        let (welcome_b, _commit_b, _e) = owner.add_member(&kp_b).unwrap();
        b.join(&welcome_b).unwrap();

        // C joins; existing member B processes the commit, C bootstraps from its Welcome.
        let (mut c, kp_c) = GroupCgkaState::new_joiner(3, GroupHierarchyMode::Flat).unwrap();
        let (welcome_c, commit_c, epoch_c) = owner.add_member(&kp_c).unwrap();
        b.process_commit(&commit_c, epoch_c).unwrap();
        c.join(&welcome_c).unwrap();

        // Owner sends; B and C decrypt to the same plaintext; the raw bytes are not the plaintext.
        let plaintext = b"fire mission: grid 1234 5678";
        let wire = owner.encrypt_message(plaintext).unwrap();
        assert!(!wire.windows(plaintext.len()).any(|w| w == plaintext));
        assert_eq!(b.decrypt_message(&wire).unwrap(), plaintext);
        assert_eq!(c.decrypt_message(&wire).unwrap(), plaintext);
        let _ = key;
    }

    #[test]
    fn owner_removes_member_then_message_excludes_them() {
        let mut owner = GroupCgkaState::new_owner(1, GroupHierarchyMode::Flat).unwrap();
        let (mut b, kp_b) = GroupCgkaState::new_joiner(2, GroupHierarchyMode::Flat).unwrap();
        let (welcome_b, _commit_b, _e) = owner.add_member(&kp_b).unwrap();
        b.join(&welcome_b).unwrap();

        // Remove B by cid; B can no longer decrypt a post-removal message.
        let (commit_r, epoch_r) = owner.remove_member_by_cid(2).unwrap().unwrap();
        // (B applying its own removal commit cannot reach the new epoch secret.)
        let _ = b.process_commit(&commit_r, epoch_r);
        let wire = owner.encrypt_message(b"after removal").unwrap();
        assert!(b.decrypt_message(&wire).is_err());

        // Removing an unknown cid is a no-op.
        assert!(owner.remove_member_by_cid(999).unwrap().is_none());
    }

    #[test]
    fn non_owner_cannot_commit() {
        let (mut b, _kp) = GroupCgkaState::new_joiner(2, GroupHierarchyMode::Flat).unwrap();
        assert!(b.add_member(b"x").is_err());
        assert!(b.remove_member(0).is_err());
        assert!(b.remove_member_by_cid(1).is_err());
    }
}
