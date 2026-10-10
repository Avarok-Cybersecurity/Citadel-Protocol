//! Object-transfer failure notification helpers for [`StateContainerInner`].

use super::includes::*;
use super::OutboundFileTransfer;
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

    /// Deliver `Fail(reason)` to the local ObjectTransferHandle for `file_key`
    /// and drop it. Returns whether a handle was present.
    ///
    /// A transfer that ends without its last ack must end its handle too:
    /// the handle only ever ends on `TransferComplete` or `Fail`, so a path
    /// that tears the transfer down without either leaves the caller waiting
    /// forever on a session that stays up.
    pub(crate) fn fail_object_transfer_handle(&self, file_key: &FileKey, reason: String) -> bool {
        match self.file_transfer_handles.remove(file_key) {
            Some((_, tx)) => {
                let _ = tx.unbounded_send(ObjectTransferStatus::Fail(reason));
                true
            }
            None => false,
        }
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
                transfer.halt();
            }
        }
        let ended: usize = inbound.len() + outbound.len();
        for key in inbound.iter().chain(outbound.iter()) {
            self.fail_object_transfer_handle(key, reason.to_string());
        }
        if ended > 0 {
            log::warn!(target: "citadel", "Ended {ended} object transfer(s) with {peer_cid}: {reason}");
        }
        ended
    }
}

impl OutboundFileTransfer {
    /// Stop the scrambler and tell the waiting streaming task not to begin.
    ///
    /// Dropping `start` instead resolves the task's receiver with `RecvError`,
    /// which it logs as an error although nothing went wrong.
    pub(crate) fn halt(&mut self) {
        if let Some(stop) = self.stop_tx.take() {
            let _ = stop.send(());
        }
        if let Some(start) = self.start.take() {
            let _ = start.send(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio::sync::oneshot;
    use citadel_types::proto::{TransferType, VirtualObjectMetadata};

    fn transfer() -> (
        OutboundFileTransfer,
        oneshot::Receiver<bool>,
        oneshot::Receiver<()>,
    ) {
        let (start, start_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let (next_gs_alerter, _rx) = crate::proto::outbound_sender::unbounded();
        let transfer = OutboundFileTransfer {
            metadata: VirtualObjectMetadata {
                name: "f".into(),
                date_created: String::new(),
                author: String::new(),
                plaintext_length: 0,
                group_count: 0,
                object_id: ObjectId(1),
                cid: 1,
                transfer_type: TransferType::FileTransfer,
            },
            ticket: Ticket(1),
            target_cid: 2,
            next_gs_alerter,
            start: Some(start),
            stop_tx: Some(stop_tx),
        };
        (transfer, start_rx, stop_rx)
    }

    #[citadel_io::tokio::test]
    async fn halting_tells_the_waiting_task_not_to_begin() {
        let (mut transfer, start_rx, stop_rx) = transfer();
        transfer.halt();
        assert_eq!(start_rx.await, Ok(false));
        assert_eq!(stop_rx.await, Ok(()));
    }

    /// Negative control: dropping the record, which is what the end paths did,
    /// surfaces to the waiting task as the error `halt` exists to avoid.
    #[citadel_io::tokio::test]
    async fn dropping_the_record_is_what_produced_the_recv_error() {
        let (transfer, start_rx, _stop_rx) = transfer();
        drop(transfer);
        assert!(start_rx.await.is_err());
    }
}
