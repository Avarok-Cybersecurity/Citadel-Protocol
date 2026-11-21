//! A member taking over as its group's committer when the owner leaves (see
//! `peer::group_succession`).
//!
//! TreeKEM lets any member commit from its own leaf. The successor removes the departed owner's
//! leaf at once, re-keying its own path, so the owner that left can open nothing sent after.

use super::GroupCgkaState;
use crate::error::NetworkError;
use citadel_io::{error, ErrorCode};

impl GroupCgkaState {
    /// This member owns the group now: it commits from here on, and its first Commit removes
    /// `previous`, the owner that left. Returns that Commit and its epoch, or `None` when
    /// `previous` holds no leaf in this member's tree. Only a flat group is handed on.
    pub fn take_ownership(
        &mut self,
        previous: u64,
    ) -> Result<Option<(Vec<u8>, u64)>, NetworkError> {
        if !self.is_flat() {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        if self.is_pending_join() {
            return Err(error!(ErrorCode::ProtoGroupCgkaNoState));
        }
        self.is_owner = true;
        // Ownership is part of what is kept, so the next save writes it.
        self.saved = None;
        self.remove_member_by_cid(previous)
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::peer::group_cgka::GroupCgkaState;
    use citadel_types::proto::GroupHierarchyMode;

    const OWNER: u64 = 1;
    const SUCCESSOR: u64 = 3;
    const MEMBER: u64 = 2;

    /// An owner with two members, every one at the same epoch.
    fn trio() -> (GroupCgkaState, GroupCgkaState, GroupCgkaState) {
        let mut owner = GroupCgkaState::new_owner(OWNER, GroupHierarchyMode::Flat).unwrap();
        let (mut member, kp_m) =
            GroupCgkaState::new_joiner(MEMBER, GroupHierarchyMode::Flat).unwrap();
        let (welcome_m, _, _, _) = owner.add_member(&kp_m).unwrap();
        member.join(&welcome_m).unwrap();
        let (mut successor, kp_s) =
            GroupCgkaState::new_joiner(SUCCESSOR, GroupHierarchyMode::Flat).unwrap();
        let (welcome_s, commit_s, epoch_s, _) = owner.add_member(&kp_s).unwrap();
        member.process_commit(&commit_s, epoch_s).unwrap();
        successor.join(&welcome_s).unwrap();
        (owner, member, successor)
    }

    #[test]
    fn the_successor_cuts_the_departed_owner_out_and_the_group_reads_on() {
        let (mut owner, mut member, mut successor) = trio();
        assert!(!successor.is_owner());
        let (commit, epoch) = successor
            .take_ownership(OWNER)
            .unwrap()
            .expect("a leaf to remove");
        assert!(successor.is_owner());
        member.process_commit(&commit, epoch).unwrap();
        let _ = owner.process_commit(&commit, epoch);

        let from_member = member.encrypt_message(b"after the owner left").unwrap();
        assert_eq!(
            successor.decrypt_message(&from_member).unwrap(),
            (MEMBER, b"after the owner left".to_vec())
        );
        let from_successor = successor.encrypt_message(b"from the new owner").unwrap();
        assert!(
            owner.decrypt_message(&from_successor).is_err(),
            "the owner that left opened a message sent after its removal"
        );
        assert_eq!(
            member.decrypt_message(&from_successor).unwrap().1,
            b"from the new owner"
        );
    }

    #[test]
    fn the_successor_adds_and_removes_members() {
        let (_owner, mut member, mut successor) = trio();
        let (commit, epoch) = successor.take_ownership(OWNER).unwrap().unwrap();
        member.process_commit(&commit, epoch).unwrap();
        let (mut joiner, kp) = GroupCgkaState::new_joiner(4, GroupHierarchyMode::Flat).unwrap();
        let (welcome, commit, epoch, _) = successor.add_member(&kp).unwrap();
        member.process_commit(&commit, epoch).unwrap();
        joiner.join(&welcome).unwrap();
        let wire = member.encrypt_message(b"hello joiner").unwrap();
        assert_eq!(joiner.decrypt_message(&wire).unwrap().1, b"hello joiner");
        assert!(successor.remove_member_by_cid(MEMBER).unwrap().is_some());
    }

    #[test]
    fn a_member_still_joining_cannot_take_over() {
        let (mut joiner, _kp) =
            GroupCgkaState::new_joiner(MEMBER, GroupHierarchyMode::Flat).unwrap();
        assert!(joiner.take_ownership(OWNER).is_err());
        assert!(!joiner.is_owner());
    }

    #[test]
    fn ownership_is_kept_with_the_stored_state() {
        let (_owner, _member, mut successor) = trio();
        let _ = successor.take_ownership(OWNER).unwrap();
        assert!(successor.take_unsaved());
        let stored = successor.export().unwrap().unwrap();
        assert!(GroupCgkaState::import(&stored).unwrap().is_owner());
    }
}
