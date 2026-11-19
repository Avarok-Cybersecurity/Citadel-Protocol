//! Opening the groups of a RE-VFS object pulled back from where it was stored.
//!
//! A group sealed under the account's key opens with that key. A group sealed before keys
//! existed opens with the session's static auxiliary ratchet, and the object's handle is told
//! ([`ObjectTransferStatus::LegacySealReceived`]) so the application seals it again.

use super::includes::*;
use citadel_crypt::revfs_seal::{self, Opened};
use citadel_io::ErrorCode;

impl<R: Ratchet> StateContainerInner<R> {
    /// Returns the group's bytes, and whether it was sealed the old way.
    pub(super) fn open_revfs_group(
        &self,
        object_id: ObjectId,
        group_index: u64,
        level: SecurityLevel,
        group: Vec<u8>,
    ) -> Result<(Vec<u8>, bool), NetworkError> {
        // An empty object travels as filler the receiver discards: there is nothing to open.
        if group.is_empty() {
            return Ok((group, false));
        }
        let cnac = self
            .cnac
            .as_ref()
            .ok_or_else(|| citadel_io::error!(ErrorCode::RevfsUnsupported))?;
        let cid = cnac.get_cid();
        let key = self.revfs_key(cid);
        match revfs_seal::open(key.as_ref(), cid, object_id.0, group_index, level, &group)? {
            Opened::Sealed(bytes) => Ok((bytes, false)),
            Opened::Legacy { foreign_key } => {
                log::warn!(target: "citadel", "RE-VFS object {object_id} group {group_index} is sealed the old way; opening it with the static auxiliary ratchet");
                cnac.get_static_auxiliary_ratchet()
                    .local_decrypt(group, level)
                    .map(|bytes| (bytes, true))
                    .map_err(|err| {
                        if foreign_key {
                            citadel_io::error!(ErrorCode::RevfsSealedUnderAnotherKey)
                        } else {
                            NetworkError::msg(err.into_string())
                        }
                    })
            }
        }
    }

    /// Tells the object's handle, once, that it holds groups sealed the old way.
    pub(super) fn report_legacy_seal(&self, file_key: FileKey, level: SecurityLevel) {
        let Some(mut file) = self.inbound_files.get_mut(&file_key) else {
            return;
        };
        if std::mem::replace(&mut file.legacy_seal_reported, true) {
            return;
        }
        drop(file);
        if let Some(handle) = self.file_transfer_handles.get(&file_key) {
            if let Err(err) = handle.unbounded_send(ObjectTransferStatus::LegacySealReceived(level))
            {
                log::warn!(target: "citadel", "Unable to tell the handle its object is sealed the old way: {err:?}");
            }
        }
    }
}
