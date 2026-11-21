//! Replacing this member's leaf after its state came from the server's sealed copy (see
//! `peer::group_backup`). Any device of the account may have held that state, so the member
//! publishes a KeyPackage for a fresh leaf; the owner's next Commit replaces the old leaf with it,
//! and from that epoch on the group's keys are sealed to the new leaf only. Until the Welcome
//! for it arrives, the member reads and sends on the state it has.

use super::{fresh_secret, ser_err, GroupCgkaState};
use crate::error::NetworkError;
use citadel_treekem::KeyPackage;
use citadel_user::serialization::SyncIO;

impl GroupCgkaState {
    /// Marks a state read back from the server's sealed copy: its leaf is to be replaced.
    pub fn restored_from_backup(mut self) -> Self {
        self.needs_new_leaf = true;
        self
    }

    /// Whether this member's leaf is still to be replaced.
    pub fn needs_new_leaf(&self) -> bool {
        self.needs_new_leaf
    }

    /// A KeyPackage for a fresh leaf of `cid`, whose secret this state keeps for the Welcome that
    /// answers it. The current group state is kept until then.
    pub fn new_leaf_key_package(&mut self, cid: u64) -> Result<Vec<u8>, NetworkError> {
        let secret = fresh_secret();
        let payload = KeyPackage::generate(cid, &secret)?
            .serialize_to_vector()
            .map_err(|_| ser_err("key_package"))?;
        self.own_leaf_secret = secret;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::GroupHierarchyMode;

    /// A state restored on a new device replaces its leaf; from the owner's next epoch on, the
    /// copy another device still holds reads nothing, and the new device reads and sends as before.
    #[test]
    fn a_replaced_leaf_shuts_out_every_other_copy_of_the_old_state() {
        let mut owner = GroupCgkaState::new_owner(1, GroupHierarchyMode::Flat).unwrap();
        let (mut member, kp) = GroupCgkaState::new_joiner(2, GroupHierarchyMode::Flat).unwrap();
        let (welcome, _, _, _) = owner.add_member(&kp).unwrap();
        member.join(&welcome).unwrap();

        let kept = member
            .export()
            .unwrap()
            .expect("a flat member's state is kept");
        let mut old_device = GroupCgkaState::import(&kept).unwrap();
        let mut new_device = GroupCgkaState::import(&kept)
            .unwrap()
            .restored_from_backup();
        assert!(new_device.needs_new_leaf());
        let before = owner.encrypt_message(b"before").unwrap();
        assert_eq!(new_device.decrypt_message(&before).unwrap().1, b"before");
        assert_eq!(old_device.decrypt_message(&before).unwrap().1, b"before");

        let kp = new_device.new_leaf_key_package(2).unwrap();
        let meanwhile = new_device.encrypt_message(b"meanwhile").unwrap();
        assert_eq!(
            owner.decrypt_message(&meanwhile).unwrap(),
            (2, b"meanwhile".to_vec())
        );
        let (welcome, commit, epoch, _) = owner.add_member(&kp).unwrap();
        new_device.join(&welcome).unwrap();
        assert!(!new_device.needs_new_leaf());
        let _ = old_device.process_commit(&commit, epoch);

        let after = owner.encrypt_message(b"after").unwrap();
        assert_eq!(new_device.decrypt_message(&after).unwrap().1, b"after");
        assert!(
            old_device.decrypt_message(&after).is_err(),
            "the old device still reads the group"
        );
        let sent = new_device.encrypt_message(b"from the new leaf").unwrap();
        assert_eq!(owner.decrypt_message(&sent).unwrap().0, 2);
    }
}
