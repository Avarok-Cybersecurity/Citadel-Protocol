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

    /// End every object transfer riding the P2P link to `peer_cid`, both
    /// directions, with `reason` -- called when that link is torn down.
    ///
    /// A transfer only ended on its last ack or a stage error. When its link
    /// dropped mid-way, neither came: both sides' tick streams stayed open at 0%,
    /// the records stayed in `inbound_files` / `outbound_files`, and every later
    /// offer to that peer queued behind the dead one (seen live, 2026-09-26).
    /// Returns how many were ended.
    pub(crate) fn fail_transfers_with_peer(&mut self, peer_cid: u64, reason: &str) -> usize {
        fn involves(target: &VirtualTargetType, peer: u64) -> bool {
            match target {
                VirtualConnectionType::LocalGroupPeer {
                    session_cid,
                    peer_cid,
                }
                | VirtualConnectionType::ExternalGroupPeer {
                    session_cid,
                    peer_cid,
                    ..
                } => *session_cid == peer || *peer_cid == peer,
                _ => false,
            }
        }
        let inbound: Vec<FileKey> = self
            .inbound_files
            .iter()
            .filter(|entry| involves(&entry.value().virtual_target, peer_cid))
            .map(|entry| *entry.key())
            .collect();
        let outbound: Vec<FileKey> = self
            .outbound_files
            .iter()
            .filter(|(_, transfer)| transfer.target_cid == peer_cid)
            .map(|(key, _)| *key)
            .collect();
        for key in &inbound {
            let _ = self.inbound_files.remove(key);
        }
        for key in &outbound {
            if let Some(mut transfer) = self.outbound_files.remove(key) {
                if let Some(stop) = transfer.stop_tx.take() {
                    let _ = stop.send(());
                }
            }
        }
        let ended: usize = inbound.len() + outbound.len();
        for key in inbound.iter().chain(outbound.iter()) {
            if let Some((_, tx)) = self.file_transfer_handles.remove(key) {
                let _ = tx.unbounded_send(ObjectTransferStatus::Fail(reason.to_string()));
            }
        }
        if ended > 0 {
            log::warn!(target: "citadel", "Ended {ended} object transfer(s) with {peer_cid}: {reason}");
        }
        ended
    }
}
