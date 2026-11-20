//! Opening the groups of a RE-VFS object pulled back from where it was stored: each opens under
//! the account's key, or is refused.

use super::includes::*;
use citadel_crypt::revfs_seal;
use citadel_io::ErrorCode;

impl<R: Ratchet> StateContainerInner<R> {
    /// Returns the group's bytes.
    pub(super) fn open_revfs_group(
        &self,
        object_id: ObjectId,
        group_index: u64,
        level: SecurityLevel,
        group: Vec<u8>,
    ) -> Result<Vec<u8>, NetworkError> {
        // An empty object travels as filler the receiver discards: there is nothing to open.
        if group.is_empty() {
            return Ok(group);
        }
        let cnac = self
            .cnac
            .as_ref()
            .ok_or_else(|| citadel_io::error!(ErrorCode::RevfsUnsupported))?;
        let cid = cnac.get_cid();
        let key = self.revfs_key(cid);
        Ok(revfs_seal::open(
            key.as_ref(),
            cid,
            object_id.0,
            group_index,
            level,
            &group,
        )?)
    }
}
