//! Object-transfer failure notification helpers for [`StateContainerInner`].

use super::includes::*;
use citadel_io::{error, Dbg, ErrorCode};

impl<R: Ratchet> StateContainerInner<R> {
    pub fn notify_object_transfer_handle_failure<T: Into<String>>(
        &self,
        header: &HdpHeader,
        error_message: T,
        object_id: ObjectId,
    ) -> Result<(), NetworkError> {
        let target_cid = header.session_cid.get();
        self.notify_object_transfer_handle_failure_with(target_cid, object_id, error_message)
    }

    pub fn notify_object_transfer_handle_failure_with<T: Into<String>>(
        &self,
        _target_cid: u64,
        object_id: ObjectId,
        error_message: T,
    ) -> Result<(), NetworkError> {
        // let group_key = GroupKey::new(target_cid, group_id, object_id);
        let file_key = FileKey::new(object_id);
        let file_transfer_handle = self
            .file_transfer_handles
            .get_mut(&file_key)
            .ok_or_else(|| error!(ErrorCode::FileTransferHandleKeyMissing, Dbg(file_key)))?;

        file_transfer_handle
            .unbounded_send(ObjectTransferStatus::Fail(error_message.into()))
            .map_err(|err| NetworkError::generic(err.to_string()))
    }
}
